package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/store"
)

// Provider accesses an exact service/account pair. Name listing is exclusively
// a manifest operation and must not enumerate a provider.
type Provider interface {
	Get(service, account string) ([]byte, error)
	Put(service, account, label string, value []byte) error
	Delete(service, account string) error
}

var ErrUnsupported = errors.New("backend not yet supported in the Go build")

type unsupported struct{}

func (unsupported) Get(string, string) ([]byte, error)       { return nil, ErrUnsupported }
func (unsupported) Put(string, string, string, []byte) error { return ErrUnsupported }
func (unsupported) Delete(string, string) error              { return ErrUnsupported }

// Dispatch validates the reference and returns a production placeholder.
// No environment variable can activate the test stub in this path.
func Dispatch(ref string) (Provider, string, string, error) { return DispatchWith(ref, nil) }

// DispatchWith permits explicit test injection, not environment activation.
func DispatchWith(ref string, provider Provider) (Provider, string, string, error) {
	backend, name, ok := strings.Cut(ref, ":")
	if !ok || (backend != "keychain" && backend != "libsecret") {
		return nil, "", "", store.ErrInvalidKeystoreName
	}
	loc := store.Locator{}
	if _, err := loc.Resolve(ref); err != nil {
		return nil, "", "", err
	}
	if provider == nil {
		provider = unsupported{}
	}
	return provider, backend, "secret/" + name, nil
}

// ListNames validates the inventory without consulting the provider.
func ListNames(dir, ref string) ([]store.ManifestRecord, error) {
	_, backend, _, err := Dispatch(ref)
	if err != nil {
		return nil, err
	}
	_, name, _ := strings.Cut(ref, ":")
	return store.ReadManifest(filepath.Join(dir, name+".keys"), backend)
}

// Stash puts and verifies the bytes before publishing the names-only record.
// A failed publish leaves an orphan; it never publishes an invalid link.
func Stash(dir, ref, key string, labels map[string]string, value []byte, provider Provider) error {
	return stashWithPublish(dir, ref, key, labels, value, provider, store.UpdateManifest)
}

// stashWithPublish injects only the publish step for failure-path tests.
func stashWithPublish(dir, ref, key string, labels map[string]string, value []byte, provider Provider, publish func(string, string, string, map[string]string, string) error) error {
	normalized, err := store.NormalizeValue(value)
	if err != nil {
		return err
	}
	p, backend, service, err := DispatchWith(ref, provider)
	if err != nil {
		return err
	}
	if err := store.ValidateIdentity(key, labels); err != nil {
		return err
	}
	if err := store.ValidateDirectory(dir); err != nil {
		return err
	}
	_, name, _ := strings.Cut(ref, ":")
	path := filepath.Join(dir, name+".keys")
	records, err := store.ReadManifest(path, backend)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	account := ""
	wanted := store.CanonicalLabels(labels)
	for _, r := range records {
		if r.Key == key && store.CanonicalLabels(r.Labels) == wanted {
			account = r.Account
			break
		}
	}
	if account == "" {
		account, err = store.NewAccount()
		if err != nil {
			return err
		}
	}
	label := "secret/" + name + "/" + key
	if wanted != "" {
		label += "/" + wanted
	}
	if err = p.Put(service, account, label, normalized); err != nil {
		if errors.Is(err, ErrUnsupported) {
			return ErrUnsupported
		}
		return errors.New("backend put failed")
	}
	got, err := p.Get(service, account)
	if err != nil || !bytes.Equal(got, normalized) {
		return errors.New("backend lookup failed")
	}
	if err := publish(path, backend, key, labels, account); err != nil {
		return errors.New("manifest publish failed")
	}
	return nil
}
