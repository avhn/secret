package store

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/secure"
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

// withLock serializes read-modify-write operations across processes. Stale locks
// are deliberately never stolen: the operator must verify the owner and remove them.
func WithWriteLock(dir string, work func() error) error {
	return withLock(dir, lockWait, work)
}

var lockWait = 3 * time.Second

// SetLockWaitForTest changes the process-wide write-lock budget for tests only.
// Call it before starting writers and restore it after all writers have stopped.
// Tests using it must not run in parallel with other store operations or setters.
func SetLockWaitForTest(d time.Duration) (restore func()) {
	previous := lockWait
	lockWait = d
	return func() { lockWait = previous }
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
	if secure.ValidateStorePath(file) != nil || secure.ValidateStorePath(secretsDir) != nil {
		return ErrInvalidKeystoreName
	}
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
	defer secure.Clear(normalized)
	assignmentLine := append(append([]byte(key+"="), normalized...), '\n')
	defer secure.Clear(assignmentLine)
	return WithWriteLock(secretsDir, func() error {
		dir := filepath.Dir(file)
		root, err := openWriteRoot(dir)
		if err != nil {
			return err
		}
		defer root.Close()
		name := filepath.Base(file)
		source, err := readRegular(root, name)
		defer secure.Clear(source)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("cannot read store")
		}
		if os.IsNotExist(err) {
			source = nil
		}
		if IsAgeStoreBytes(source) {
			return ErrAge
		}
		result := rewriteStash(source, key, CanonicalLabels(labels), assignmentLine)
		defer secure.Clear(result)
		return atomicReplace(root, name, result)
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
