package backend

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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

var providerPair = regexp.MustCompile(`^secret/[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
var providerAccount = regexp.MustCompile(`^[0-9a-f]{32}$`)

// validProviderPair rejects option injection even for direct provider calls.
func validProviderPair(service, account string) bool {
	return providerPair.MatchString(service) && providerAccount.MatchString(account)
}

// commandRunner carries provider input on stdin and retains output only in memory.
// Callers must never include provider output or command errors in returned errors.
type commandRunner func(name string, args []string, input []byte) ([]byte, []byte, error)

const providerOutputLimit = 1 << 20

// limitedOutput cancels the provider as soon as either captured stream exceeds the bound.
type limitedOutput struct {
	bytes.Buffer
	cancel   context.CancelFunc
	exceeded bool
}

func (w *limitedOutput) Write(p []byte) (int, error) {
	if len(p) > providerOutputLimit-w.Len() {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("provider output limit exceeded")
	}
	return w.Buffer.Write(p)
}

// ReadFrom routes exec's optimized pipe copy through the same output bound.
func (w *limitedOutput) ReadFrom(r io.Reader) (int64, error) {
	chunk := make([]byte, 8192)
	var total int64
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			written, writeErr := w.Write(chunk[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if err == io.EOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// runProvider bounds provider lifetime, inherited pipes, and captured output.
func runProvider(name string, args []string, input []byte) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	configureProviderProcess(cmd)
	cmd.WaitDelay = 250 * time.Millisecond
	cmd.Stdin = bytes.NewReader(input)
	stdout := &limitedOutput{cancel: cancel}
	stderr := &limitedOutput{cancel: cancel}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		stopProviderProcess(cmd)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, nil, errors.New("provider output limit exceeded")
	}
	if err != nil {
		return nil, nil, errors.New("provider call failed")
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

// Dispatch validates the reference and selects the provider. Only the
// secretstub test build can select a directory provider through the environment.
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
		provider = testProvider(backend)
	}
	if provider == nil {
		if backend == "libsecret" {
			provider = libsecret{run: runProvider}
		} else {
			selected := newKeychain(runProvider)
			if !selected.valid {
				return nil, "", "", errors.New("SECRET_KEYCHAIN must be an absolute path without spaces or quoting")
			}
			provider = selected
		}
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
	return stashWithPublish(dir, ref, key, labels, value, provider, store.UpdateManifestLocked)
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
	_, name, _ := strings.Cut(ref, ":")
	path := filepath.Join(dir, name+".keys")
	return store.WithWriteLock(dir, func() error {
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
		if backend == "libsecret" {
			label = "secret " + name + " " + key
			if wanted != "" {
				label += " [" + wanted + "]"
			}
		} else if wanted != "" {
			label += "/" + wanted
		}
		if err = p.Put(service, account, label, normalized); err != nil {
			if errors.Is(err, ErrUnsupported) || errors.Is(err, ErrValueTooLarge) {
				return err
			}
			return errors.New("backend put failed")
		}
		got, err := p.Get(service, account)
		if err != nil || !bytes.Equal(got, normalized) {
			return errors.New("backend lookup failed")
		}
		if err := stubPublishFailure(p); err != nil {
			return errors.New("manifest publish failed")
		}
		if err := publish(path, backend, key, labels, account); err != nil {
			return errors.New("manifest publish failed")
		}
		return nil
	})
}
