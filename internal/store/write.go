package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var errInvalidValue = errors.New("invalid value (empty, whitespace, quotes, newline, NUL, or CR)")

// NormalizeValue removes at most one terminal LF. Errors never include value bytes.
func NormalizeValue(value []byte) ([]byte, error) {
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
	}
	if len(value) == 0 || bytes.ContainsAny(value, "\x00\r\n") || isSpace(value[0]) || isSpace(value[len(value)-1]) || (len(value) > 1 && (value[0] == '\'' || value[0] == '"') && value[len(value)-1] == value[0]) {
		return nil, errInvalidValue
	}
	return append([]byte(nil), value...), nil
}
func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}
func newToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("cannot generate write token")
	}
	return hex.EncodeToString(b[:]), nil
}

// ValidateDirectory rejects a symlinked or non-directory secrets location.
// Like Bash, it checks only the final component, not every ancestor.
func ValidateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret directory must not be a symlink")
	}
	return nil
}

// withLock serializes read-modify-write operations across processes. Stale locks
// are deliberately never stolen: the operator must verify the owner and remove them.
func WithWriteLock(dir string, work func() error) error {
	return withLock(dir, lockWait, work)
}

var lockWait = 3 * time.Second

func withLock(dir string, wait time.Duration, work func() error) error {
	if err := ValidateDirectory(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create secret directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret directory must not be a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open secret directory")
	}
	defer root.Close()
	if err := root.Chmod(".", 0700); err != nil {
		return errors.New("cannot protect secret directory")
	}
	return withRootLock(root, wait, func(*os.Root) error { return work() })
}

// withRootLock keeps the lock, callback and publication on one directory handle.
func withRootLock(root *os.Root, wait time.Duration, work func(*os.Root) error) error {
	const lock = ".write-lock"
	var err error
	deadline := time.Now().Add(wait)
	for {
		err = root.Mkdir(lock, 0700)
		if err == nil {
			break
		}
		if !lockBusy(err) {
			return errors.New("cannot acquire write lock")
		}
		if !time.Now().Before(deadline) {
			if !os.IsExist(err) {
				return errors.New("cannot acquire write lock")
			}
			return fmt.Errorf("write lock timed out after %d s; verify its owner then manually remove .write-lock (never auto-stolen)", int(wait/time.Second))
		}
		time.Sleep(100 * time.Millisecond)
	}
	token, err := newToken()
	if err != nil {
		_ = root.Remove(lock)
		return err
	}
	if err = root.WriteFile(filepath.Join(lock, "token"), []byte(token+"\n"), 0600); err != nil {
		_ = root.Remove(filepath.Join(lock, "token"))
		_ = root.Remove(lock)
		return errors.New("cannot write lock token")
	}
	defer func() {
		owner, e := root.ReadFile(filepath.Join(lock, "token"))
		if e == nil && string(owner) == token+"\n" {
			_ = root.Remove(filepath.Join(lock, "token"))
			_ = root.Remove(lock)
		}
	}()
	if err := cleanStaleScratch(root); err != nil {
		return err
	}
	return work(root)
}

// lockBusy reports contention. Windows denies access to a lock directory whose
// delete is still pending, so a releasing owner briefly looks like a denial there.
func lockBusy(err error) bool {
	return os.IsExist(err) || runtime.GOOS == "windows" && os.IsPermission(err)
}

// A fresh owner may remove only our marked scratch directories after the
// operator verifies and clears a killed writer's tokened lock.
func cleanStaleScratch(root *os.Root) error {
	parent, err := root.Open(".")
	if err != nil {
		return errors.New("cannot inspect private write directory")
	}
	defer parent.Close()
	entries, err := parent.ReadDir(-1)
	if err != nil {
		return errors.New("cannot inspect private write directory")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".secret-stash.") {
			continue
		}
		path := entry.Name()
		marker, err := root.Lstat(filepath.Join(path, "owner"))
		if err != nil || !marker.Mode().IsRegular() {
			continue
		}
		body, err := root.ReadFile(filepath.Join(path, "owner"))
		if err != nil || string(body) != "secret-stash-v1\n" {
			continue
		}
		if err := root.RemoveAll(path); err != nil {
			return errors.New("cannot clean private write directory")
		}
	}
	return nil
}

// ValidateIdentity checks a key and complete selector set before any write.
func ValidateIdentity(key string, labels map[string]string) error {
	if !keyName.MatchString(key) {
		return errors.New("invalid key name")
	}
	for n, v := range labels {
		if !keyName.MatchString(n) || !labelValue.MatchString(v) {
			return ErrInvalidSelector
		}
	}
	return nil
}

func regularTarget(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing symlink or non-regular write target")
	}
	return nil
}

// readRegular checks the final component through the anchored directory and
// opens without following final symlinks on platforms with O_NOFOLLOW.
func readRegular(root *os.Root, name string) ([]byte, error) {
	if err := regularTarget(root, name); err != nil {
		return nil, err
	}
	file, err := openNoFollow(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("refusing symlink or non-regular write target")
	}
	return io.ReadAll(file)
}

// atomicReplace creates a private sibling and publishes only after syncing data.
func atomicReplace(root *os.Root, name string, data []byte) error {
	return atomicReplaceChecked(root, name, data, false, nil)
}

func atomicReplaceChecked(root *os.Root, name string, data []byte, strict bool, checkpoint func(string) error) error {
	check := func(phase string) error {
		if checkpoint != nil {
			return checkpoint(phase)
		}
		return nil
	}
	if err := regularTarget(root, name); err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	scratch := ".secret-stash." + token
	if err := root.Mkdir(scratch, 0700); err != nil {
		return errors.New("cannot create private write directory")
	}
	defer root.RemoveAll(scratch)
	// A crash before the marker exists leaves only an empty unmarked directory.
	if err := root.WriteFile(filepath.Join(scratch, "owner"), []byte("secret-stash-v1\n"), 0600); err != nil {
		return errors.New("cannot create private write directory")
	}
	file, err := root.OpenFile(filepath.Join(scratch, "replacement"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("atomic store update failed")
	}
	if err = check("scratch-write"); err == nil {
		_, err = file.Write(data)
	}
	if err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = check("file-sync"); err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("atomic store update failed")
	}
	if err = regularTarget(root, name); err != nil {
		return err
	}
	if err = check("rename"); err == nil {
		err = root.Rename(filepath.Join(scratch, "replacement"), name)
	}
	if err != nil {
		return errors.New("atomic store update failed")
	}
	// Age requires directory durability. A post-publication failure is not rollback.
	if strict {
		if check("directory-sync") != nil {
			return ErrAgeDurability
		}
		parent, e := root.Open(".")
		if e != nil {
			return ErrAgeDurability
		}
		defer parent.Close()
		if parent.Sync() != nil {
			return ErrAgeDurability
		}
		return nil
	}
	// Publishing succeeded; directory sync only hardens legacy crash durability.
	if runtime.GOOS != "windows" {
		if parentFile, e := root.Open("."); e == nil {
			_ = parentFile.Sync()
			_ = parentFile.Close()
		}
	}
	return nil
}

// Stash writes a single exact key and label identity without changing peers.
func Stash(file, key string, labels map[string]string, value []byte) error {
	dir := os.Getenv("SECRETS_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return errors.New("cannot locate secret directory")
		}
		dir = filepath.Join(home, ".secrets")
	}
	return StashWithSecretsDir(dir, file, key, labels, value)
}

// StashWithSecretsDir locks the Bash secrets directory even for an explicit file.
func StashWithSecretsDir(secretsDir, file, key string, labels map[string]string, value []byte) error {
	if !keyName.MatchString(key) {
		return errors.New("invalid key name")
	}
	for n, v := range labels {
		if !keyName.MatchString(n) || !labelValue.MatchString(v) {
			return ErrInvalidSelector
		}
	}
	normalized, err := NormalizeValue(value)
	if err != nil {
		return err
	}
	if normalized[0] == '\'' || normalized[0] == '"' || normalized[len(normalized)-1] == '\'' || normalized[len(normalized)-1] == '"' {
		normalized = append(append([]byte{'\''}, normalized...), '\'')
	}
	assignmentLine := append(append([]byte(key+"="), normalized...), '\n')
	return WithWriteLock(secretsDir, func() error {
		dir := filepath.Dir(file)
		if err := ValidateDirectory(dir); err != nil {
			return err
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return errors.New("cannot create secret directory")
		}
		if err := ValidateDirectory(dir); err != nil {
			return err
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return errors.New("cannot open store directory")
		}
		defer root.Close()
		name := filepath.Base(file)
		source, err := readRegular(root, name)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("cannot read store")
		}
		if os.IsNotExist(err) {
			source = nil
		}
		if IsAgeStoreBytes(source) {
			return ErrAge
		}
		return atomicReplace(root, name, rewriteStash(source, key, CanonicalLabels(labels), assignmentLine))
	})
}

func validHeader(line []byte) (string, bool) {
	match := header.FindSubmatch(line)
	if match == nil {
		return "", false
	}
	pairs := strings.Split(string(match[1]), ",")
	seen := make(map[string]bool)
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		name, _, _ := strings.Cut(pair, "=")
		if seen[name] {
			return "", false
		}
		seen[name] = true
	}
	if len(match[1]) == 0 {
		return "", true
	}
	labels := make(map[string]string)
	for _, pair := range pairs {
		n, v, _ := strings.Cut(pair, "=")
		labels[n] = v
	}
	return CanonicalLabels(labels), true
}
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n')
		if n < 0 {
			lines = append(lines, data)
			break
		}
		lines = append(lines, data[:n+1])
		data = data[n+1:]
	}
	return lines
}
func contentLine(line []byte) []byte {
	if bytes.HasSuffix(line, []byte("\n")) {
		line = line[:len(line)-1]
		return bytes.TrimSuffix(line, []byte("\r"))
	}
	return line
}
func rewriteStash(source []byte, key, wanted string, assignmentLine []byte) []byte {
	lines := splitLines(source)
	keep := make([]bool, len(lines))
	scope := ""
	firstHeader := -1
	current := -1
	lastSection := ""
	for i, s := range lines {
		line := contentLine(s)
		if h, ok := validHeader(line); ok {
			scope = h
			if firstHeader < 0 {
				firstHeader = i
			}
			if h == wanted {
				current = i + 1
			}
			lastSection = h
		}
		keep[i] = !(scope == wanted && bytes.HasPrefix(bytes.TrimLeft(line, " \t\r\n\v\f"), []byte(key+"=")))
		if keep[i] && scope == wanted { // Also match the optional export prefix.
			m := assignment.FindSubmatch(line)
			if m != nil && string(m[1]) == key {
				keep[i] = false
			}
		}
	}
	found := wanted == "" || current >= 0
	var out []byte
	if !found {
		for i, s := range lines {
			if keep[i] {
				out = append(out, s...)
			}
		}
		if len(lines) > 0 && !bytes.HasSuffix(lines[len(lines)-1], []byte("\n")) {
			out = append(out, '\n')
		}
		if wanted != "" {
			out = append(out, []byte("["+wanted+"]\n")...)
		}
		return append(out, assignmentLine...)
	}
	at := len(lines)
	if wanted == "" {
		if lastSection != "" {
			if len(lines) > 0 && !bytes.HasSuffix(lines[len(lines)-1], []byte("\n")) {
				lines = append(lines, []byte("\n"))
				keep = append(keep, true)
			}
			lines = append(lines, []byte("[]\n"))
			keep = append(keep, true)
			at = len(lines)
		} else if firstHeader > 0 {
			at = firstHeader
		}
	} else {
		at = current
		for i := at; i < len(lines); i++ {
			if _, ok := validHeader(contentLine(lines[i])); ok {
				at = i
				break
			}
			at = i + 1
		}
	}
	offset := 0
	for i := 0; i < at; i++ {
		if keep[i] {
			offset++
		}
	}
	filtered := make([][]byte, 0, len(lines)+1)
	for i, s := range lines {
		if keep[i] {
			filtered = append(filtered, append([]byte(nil), s...))
		}
	}
	if offset > 0 && !bytes.HasSuffix(filtered[offset-1], []byte("\n")) {
		filtered[offset-1] = append(filtered[offset-1], '\n')
	}
	for _, s := range filtered[:offset] {
		out = append(out, s...)
	}
	out = append(out, assignmentLine...)
	for _, s := range filtered[offset:] {
		out = append(out, s...)
	}
	return out
}
