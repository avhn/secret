package backend

import (
	"bytes"
	"errors"
	"regexp"

	"github.com/avhn/secret/internal/store"
)

var libsecretLabel = regexp.MustCompile(`^secret [A-Za-z0-9_][A-Za-z0-9_.-]* [A-Za-z_][A-Za-z0-9_]*( \[[A-Za-z0-9_,=.\-]+\])?$`)

// validLibsecretLabel accepts only labels constructed from validated identities.
func validLibsecretLabel(label string) bool { return libsecretLabel.MatchString(label) }

// libsecret stores exact service/account pairs without enumerating the keyring.
type libsecret struct{ run commandRunner }

// Get looks up an exact pair; secret-tool does not append a newline to values.
func (p libsecret) Get(service, account string) ([]byte, error) {
	if !validProviderPair(service, account) {
		return nil, errors.New("backend lookup failed")
	}
	out, _, err := p.run("secret-tool", []string{"lookup", "service", service, "account", account}, nil)
	if err != nil {
		return nil, errors.New("backend lookup failed")
	}
	value, err := store.NormalizeValue(out)
	if err != nil || !bytes.Equal(out, value) {
		return nil, errors.New("backend lookup failed")
	}
	return value, nil
}

// Put streams bytes to secret-tool, never through process arguments.
func (p libsecret) Put(service, account, label string, value []byte) error {
	if !validProviderPair(service, account) || !validLibsecretLabel(label) {
		return errors.New("backend put failed")
	}
	value, err := store.NormalizeValue(value)
	if err != nil {
		return errors.New("backend put failed")
	}
	_, _, err = p.run("secret-tool", []string{"store", "--label=" + label, "service", service, "account", account}, value)
	if err != nil {
		return errors.New("backend put failed")
	}
	return nil
}

// Delete removes only the exact service/account pair.
func (p libsecret) Delete(service, account string) error {
	if !validProviderPair(service, account) {
		return errors.New("backend delete failed")
	}
	_, _, err := p.run("secret-tool", []string{"clear", "service", service, "account", account}, nil)
	if err != nil {
		return errors.New("backend delete failed")
	}
	return nil
}
