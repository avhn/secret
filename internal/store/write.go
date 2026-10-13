package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
func withLock(dir string, work func() error) error {
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
	lock := filepath.Join(dir, ".write-lock")
	deadline := time.Now().Add(3 * time.Second)
	for {
		err = os.Mkdir(lock, 0700)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return errors.New("cannot acquire write lock")
		}
		if !time.Now().Before(deadline) {
			return errors.New("write lock timed out after 3 s; verify its owner then manually remove .write-lock (never auto-stolen)")
		}
		time.Sleep(100 * time.Millisecond)
	}
	token, err := newToken()
	if err != nil {
		_ = os.Remove(lock)
		return err
	}
	if err = os.WriteFile(filepath.Join(lock, "token"), []byte(token+"\n"), 0600); err != nil {
		_ = os.Remove(filepath.Join(lock, "token"))
		_ = os.Remove(lock)
		return errors.New("cannot write lock token")
	}
	defer func() {
		owner, e := os.ReadFile(filepath.Join(lock, "token"))
		if e == nil && string(owner) == token+"\n" {
			_ = os.Remove(filepath.Join(lock, "token"))
			_ = os.Remove(lock)
		}
	}()
	if err := cleanStaleScratch(dir); err != nil {
		return err
	}
	return work()
}

// A fresh owner may remove only our marked scratch directories after the
// operator verifies and clears a killed writer's tokened lock.
func cleanStaleScratch(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.New("cannot inspect private write directory")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".secret-stash.") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		marker, err := os.Lstat(filepath.Join(path, "owner"))
		if err != nil || !marker.Mode().IsRegular() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(path, "owner"))
		if err != nil || string(body) != "secret-stash-v1\n" {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
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

func regularTarget(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing symlink or non-regular write target")
	}
	return nil
}

// atomicReplace creates a private sibling and publishes only after syncing data.
func atomicReplace(path string, data []byte) error {
	if err := regularTarget(path); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	scratch, err := os.MkdirTemp(parent, ".secret-stash.")
	if err != nil {
		return errors.New("cannot create private write directory")
	}
	defer os.RemoveAll(scratch)
	// A crash before the marker exists leaves only an empty unmarked directory:
	// no value is written until the marker is in place.
	if err := os.WriteFile(filepath.Join(scratch, "owner"), []byte("secret-stash-v1\n"), 0600); err != nil {
		return errors.New("cannot create private write directory")
	}
	file, err := os.OpenFile(filepath.Join(scratch, "replacement"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("atomic store update failed")
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("atomic store update failed")
	}
	if err = regularTarget(path); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(scratch, "replacement"), path); err != nil {
		return errors.New("atomic store update failed")
	}
	// The rename has published the new file, so an error here would describe a
	// store that already changed. Syncing the parent only hardens crash
	// durability (the Bash CLI never does it) and stays best-effort.
	if runtime.GOOS != "windows" {
		if parentFile, e := os.Open(parent); e == nil {
			_ = parentFile.Sync()
			_ = parentFile.Close()
		}
	}
	return nil
}

// Stash writes a single exact key and label identity without changing peers.
func Stash(file, key string, labels map[string]string, value []byte) error {
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
	dir := filepath.Dir(file)
	return withLock(dir, func() error {
		if err := regularTarget(file); err != nil {
			return err
		}
		source, err := os.ReadFile(file)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("cannot read store")
		}
		if os.IsNotExist(err) {
			source = nil
		}
		return atomicReplace(file, rewriteStash(source, key, CanonicalLabels(labels), assignmentLine))
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
	found := wanted == "" && firstHeader < 0
	if wanted != "" {
		found = current >= 0
	} else if firstHeader >= 0 {
		found = firstHeader > 0 || lastSection == ""
	}
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
