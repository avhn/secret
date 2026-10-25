package backend

import (
	"bytes"
	"errors"

	"github.com/avhn/secret/internal/secure"
)

const (
	wincredGeneric      = 1
	wincredLocalMachine = 2
	// CRED_MAX_CREDENTIAL_BLOB_SIZE and CRED_MAX_GENERIC_TARGET_NAME_LENGTH.
	wincredBlobLimit   = 5 * 512
	wincredTargetLimit = 32767
)

var errWincredMissing = errors.New("credential not found")

// wincredRecord borrows API-owned blob memory until release. Even rejected reads
// must release it. The native adapter bounds memory access before making a slice.
type wincredRecord struct {
	kind    uint32
	target  string
	blob    []byte
	size    uint32
	release func()
}

// wincredAPI is deliberately exact-target only: there is no enumeration method.
// write borrows the buffer only for its synchronous call. read transfers a record
// on success or failure so the caller can clear and release every allocation.
type wincredAPI interface {
	read(target string) (*wincredRecord, error)
	write(target string, blob []byte) error
	delete(target string) error
}

type wincred struct{ api wincredAPI }

func wincredTarget(service, account string) (string, bool) {
	if !validProviderPair(service, account) || len(service)+1+len(account) > wincredTargetLimit {
		return "", false
	}
	return service + "/" + account, true
}

func releaseWincred(record *wincredRecord) {
	if record != nil {
		secure.Clear(record.blob)
		if record.release != nil {
			record.release()
		}
	}
}

// Get verifies the exact returned identity before copying raw bytes into owned
// memory. Raw CredMan storage is not an environment or a text encoding boundary.
func (p wincred) Get(service, account string) ([]byte, error) {
	target, ok := wincredTarget(service, account)
	if !ok || p.api == nil {
		return nil, errors.New("backend lookup failed")
	}
	record, err := p.api.read(target)
	defer releaseWincred(record)
	if err != nil || record == nil || record.kind != wincredGeneric || record.target != target || record.size > wincredBlobLimit || int(record.size) != len(record.blob) {
		return nil, errors.New("backend lookup failed")
	}
	return bytes.Clone(record.blob), nil
}

// Put owns a temporary raw buffer, leaving the caller's bytes unchanged. Native
// writes select generic credentials with current-user local-machine persistence.
// Labels remain in the names-only inventory, not in the credential blob.
func (p wincred) Put(service, account, label string, value []byte) error {
	target, ok := wincredTarget(service, account)
	if !ok || p.api == nil || !keychainLabel.MatchString(label) || len(value) > wincredBlobLimit {
		return errors.New("backend put failed")
	}
	owned := bytes.Clone(value)
	defer secure.Clear(owned)
	if p.api.write(target, owned) != nil {
		return errors.New("backend put failed")
	}
	return nil
}

func (p wincred) Delete(service, account string) error {
	target, ok := wincredTarget(service, account)
	if !ok || p.api == nil || p.api.delete(target) != nil {
		return errors.New("backend delete failed")
	}
	return nil
}
