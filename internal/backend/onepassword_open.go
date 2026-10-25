package backend

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/store"
)

// ReadOnlyReference is syntax-only and must precede hidden input, source reads,
// provider calls, audit setup and transaction locks. It is independent of dispatch.
func ReadOnlyReference(reference string) error {
	if strings.HasPrefix(reference, "onepassword:") {
		return ErrReadOnly
	}
	return nil
}

// OpenRead binds provider lookup and inventory to the same validated snapshot.
// The context is shared by all stores in one invocation, including authentication.
func OpenRead(ctx context.Context, directory, reference string) ([]store.ManifestRecord, Provider, string, error) {
	if strings.HasPrefix(reference, "onepassword:") {
		if !OnePasswordEnabled() {
			return nil, nil, "", ErrUnsupported
		}
		executable, err := exec.LookPath("op")
		if err != nil {
			return nil, nil, "", errOnePassword
		}
		executable, err = filepath.Abs(executable)
		if err != nil {
			return nil, nil, "", errOnePassword
		}
		return openOnePasswordRead(ctx, directory, reference, executable, os.Environ())
	}
	records, err := ListNames(directory, reference)
	if err != nil {
		return nil, nil, "", err
	}
	provider, _, service, err := Dispatch(reference)
	return records, provider, service, err
}

// Only tests call this scaffolding with an explicitly built fake executable and
// synthetic environment. No environment or build-tag switch enables dispatch.
func openOnePasswordRead(ctx context.Context, directory, reference, executable string, environment []string) ([]store.ManifestRecord, Provider, string, error) {
	if _, err := (store.Locator{}).Resolve(reference); err != nil {
		return nil, nil, "", err
	}
	kind, name, _ := strings.Cut(reference, ":")
	if kind != "onepassword" {
		return nil, nil, "", store.ErrInvalidKeystoreName
	}
	records, err := store.ReadManifestV2(filepath.Join(directory, name+".onepassword-keys"), kind)
	if err != nil {
		return nil, nil, "", errOnePassword
	}
	service := "secret/" + name
	provider, err := newOnePassword(ctx, service, records, executable, environment)
	if err != nil {
		return nil, nil, "", err
	}
	return store.ProjectManifestV2(records), provider, service, nil
}
