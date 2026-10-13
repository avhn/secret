package backend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/secret/internal/store"
)

var keychainLabel = regexp.MustCompile(`^secret/[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z_][A-Za-z0-9_]*(/[A-Za-z0-9_,=.\-]+)?$`)
var keychainPath = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)

// keychain selects a single explicit path when configured, never the search list.
type keychain struct {
	run   commandRunner
	path  string
	valid bool
}

// newKeychain validates the optional path at the boundary before any provider call.
// ErrValueTooLarge is user-facing: Bash reports the same keychain size limit.
var ErrValueTooLarge = errors.New("keychain values are limited to about 1800 bytes")

func newKeychain(run commandRunner) keychain {
	path := os.Getenv("SECRET_KEYCHAIN")
	return keychain{run: run, path: path, valid: path == "" || keychainPath.MatchString(path)}
}

// args appends the selected keychain to a direct security command.
func (p keychain) args(args ...string) []string {
	if p.path != "" {
		args = append(args, p.path)
	}
	return args
}

// parseKeychainPassword reads the labeled -g stderr, not ambiguous -w stdout.
// security returns either quoted text or a 0x-prefixed hex encoding.
func parseKeychainPassword(raw []byte) ([]byte, error) {
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if !bytes.HasPrefix(line, []byte("password: ")) {
			continue
		}
		line = bytes.TrimPrefix(line, []byte("password: "))
		if bytes.HasPrefix(line, []byte("0x")) {
			word := bytes.Fields(line)
			if len(word) == 0 || len(word[0]) <= 2 {
				break
			}
			value, err := hex.DecodeString(string(word[0][2:]))
			if err == nil {
				return value, nil
			}
			break
		}
		if len(line) >= 2 && line[0] == '"' && line[len(line)-1] == '"' {
			return bytes.Clone(line[1 : len(line)-1]), nil
		}
		break
	}
	return nil, errors.New("backend lookup failed")
}

// Get reads only the specified service/account and validates the returned bytes.
func (p keychain) Get(service, account string) ([]byte, error) {
	if !p.valid || !validProviderPair(service, account) {
		return nil, errors.New("backend lookup failed")
	}
	_, raw, err := p.run("security", p.args("find-generic-password", "-s", service, "-a", account, "-g"), nil)
	if err != nil {
		return nil, errors.New("backend lookup failed")
	}
	value, err := parseKeychainPassword(raw)
	if err != nil {
		return nil, err
	}
	normal, err := store.NormalizeValue(value)
	if err != nil || !bytes.Equal(value, normal) {
		return nil, errors.New("backend lookup failed")
	}
	return normal, nil
}

// keychainText rejects bytes security cannot reliably return through its text API.
func keychainText(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}
	for _, r := range string(value) {
		if unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
	}
	return true
}

// Put sends a hex-encoded -X command only on security -i stdin and verifies it.
func (p keychain) Put(service, account, label string, value []byte) error {
	if !p.valid || !validProviderPair(service, account) || !keychainLabel.MatchString(label) {
		return errors.New("backend put failed")
	}
	value, err := store.NormalizeValue(value)
	if err != nil || !keychainText(value) {
		return errors.New("backend put failed")
	}
	if len(value) > 1800 {
		return ErrValueTooLarge
	}
	var line strings.Builder
	line.Grow(128 + 2*len(value) + len(p.path))
	line.WriteString("add-generic-password -U -s ")
	line.WriteString(service)
	line.WriteString(" -a ")
	line.WriteString(account)
	line.WriteString(" -l ")
	line.WriteString(label)
	line.WriteString(" -X ")
	line.WriteString(hex.EncodeToString(value))
	if p.path != "" {
		line.WriteByte(' ')
		line.WriteString(p.path)
	}
	line.WriteByte('\n')
	if line.Len() > 4000 {
		return ErrValueTooLarge
	}
	_, _, err = p.run("security", []string{"-i"}, []byte(line.String()))
	if err != nil {
		return errors.New("backend put failed")
	}
	got, err := p.Get(service, account)
	if err != nil || !bytes.Equal(got, value) {
		return errors.New("backend put failed")
	}
	return nil
}

// Delete removes only the selected service/account, never a default-keychain item.
func (p keychain) Delete(service, account string) error {
	if !p.valid || !validProviderPair(service, account) {
		return errors.New("backend delete failed")
	}
	_, _, err := p.run("security", p.args("delete-generic-password", "-s", service, "-a", account), nil)
	if err != nil {
		return errors.New("backend delete failed")
	}
	return nil
}
