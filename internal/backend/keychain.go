package backend

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"regexp"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/secret/internal/secure"
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
			encoded := word[0][2:]
			value := make([]byte, hex.DecodedLen(len(encoded)))
			if _, err := hex.Decode(value, encoded); err == nil {
				return value, nil
			}
			// Decode may have written a prefix before encountering invalid hex.
			secure.Clear(value)
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
	out, raw, err := p.run("security", p.args("find-generic-password", "-s", service, "-a", account, "-g"), nil)
	defer secure.Clear(out)
	defer secure.Clear(raw)
	if err != nil {
		return nil, errors.New("backend lookup failed")
	}
	value, err := parseKeychainPassword(raw)
	if err != nil {
		return nil, err
	}
	defer secure.Clear(value)
	normal, err := store.NormalizeValue(value)
	if err != nil || !bytes.Equal(value, normal) {
		secure.Clear(normal)
		return nil, errors.New("backend lookup failed")
	}
	return normal, nil
}

// keychainText rejects bytes security cannot reliably return through its text API.
func keychainText(value []byte) bool {
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if (r == utf8.RuneError && size == 1) || unicode.IsControl(r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) {
			return false
		}
		value = value[size:]
	}
	return true
}

// Put sends a hex-encoded -X command only on security -i stdin and verifies it.
func (p keychain) Put(service, account, label string, value []byte) error {
	if !p.valid || !validProviderPair(service, account) || !keychainLabel.MatchString(label) {
		return errors.New("backend put failed")
	}
	value, err := store.NormalizeValue(value)
	defer secure.Clear(value)
	if err != nil || !keychainText(value) {
		return errors.New("backend put failed")
	}
	if len(value) > 1800 {
		return ErrValueTooLarge
	}
	const prefix = "add-generic-password -U -s "
	lineSize := len(prefix) + len(service) + len(" -a ") + len(account) + len(" -l ") + len(label) + len(" -X ") + hex.EncodedLen(len(value)) + 1
	if p.path != "" {
		lineSize += 1 + len(p.path)
	}
	if lineSize > 4000 {
		return ErrValueTooLarge
	}
	// Allocate once so growing the command cannot abandon encoded value bytes.
	line := make([]byte, 0, lineSize)
	defer secure.Clear(line)
	line = append(line, prefix...)
	line = append(line, service...)
	line = append(line, " -a "...)
	line = append(line, account...)
	line = append(line, " -l "...)
	line = append(line, label...)
	line = append(line, " -X "...)
	start := len(line)
	line = line[:start+hex.EncodedLen(len(value))]
	hex.Encode(line[start:], value)
	if p.path != "" {
		line = append(line, ' ')
		line = append(line, p.path...)
	}
	line = append(line, '\n')
	out, raw, err := p.run("security", []string{"-i"}, line)
	secure.Clear(out)
	secure.Clear(raw)
	if err != nil {
		return errors.New("backend put failed")
	}
	got, err := p.Get(service, account)
	defer secure.Clear(got)
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
	out, raw, err := p.run("security", p.args("delete-generic-password", "-s", service, "-a", account), nil)
	defer secure.Clear(out)
	defer secure.Clear(raw)
	if err != nil {
		return errors.New("backend delete failed")
	}
	return nil
}
