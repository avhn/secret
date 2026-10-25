package store

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/avhn/secret/internal/secure"
)

// V2 limits are part of the names-only container contract, not value limits.
const (
	ManifestV2Limit       = 1 << 20
	ManifestV2RecordLimit = 16 << 10
	ManifestV2Records     = 1024
)
const manifestV2Header = "secret-manifest-v2\nbackend=onepassword\n"

// OnePasswordReference contains registration metadata only, never authentication bytes.
type OnePasswordReference struct {
	Reference   string `json:"reference"`
	AccountUUID string `json:"account_uuid"`
	Auth        string `json:"auth"`
}

// ManifestV2Record uses a random local ID, not the provider's account UUID.
// Provider schemas are deliberately concrete; no extension map is accepted.
type ManifestV2Record struct {
	Key      string               `json:"key"`
	Labels   map[string]string    `json:"labels"`
	ID       string               `json:"id"`
	Provider OnePasswordReference `json:"provider"`
}

var onePasswordUUID = regexp.MustCompile(`^[a-z0-9]{26}$`)
var onePasswordField = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)

// ValidateOnePasswordReference accepts immutable vault/item IDs and literal field IDs.
// Session authentication is intentionally deferred. Titles and URL syntax are not supported.
func ValidateOnePasswordReference(p OnePasswordReference) error {
	if p.Auth != "service-account" || !onePasswordUUID.MatchString(p.AccountUUID) || !strings.HasPrefix(p.Reference, "op://") {
		return secure.ErrInvalidRequest
	}
	parts := strings.Split(strings.TrimPrefix(p.Reference, "op://"), "/")
	if len(parts) != 3 && len(parts) != 4 {
		return secure.ErrInvalidRequest
	}
	if !onePasswordUUID.MatchString(parts[0]) || !onePasswordUUID.MatchString(parts[1]) {
		return secure.ErrInvalidRequest
	}
	for _, part := range parts[2:] {
		if !onePasswordField.MatchString(part) {
			return secure.ErrInvalidRequest
		}
	}
	return nil
}

func validV2Record(r ManifestV2Record) bool {
	return len(r.Key) <= 256 && len(r.Labels) <= 128 && r.Labels != nil && validRecord(ManifestRecord{Key: r.Key, Labels: r.Labels, Account: r.ID}) && ValidateOnePasswordReference(r.Provider) == nil
}

// ParseManifestV2 requires canonical JSON lines, including an LF after each record.
// Canonical re-encoding rejects duplicate, unknown, missing and noncanonical fields.
func ParseManifestV2(data []byte, backend string) ([]ManifestV2Record, error) {
	if backend != "onepassword" || len(data) > ManifestV2Limit || !bytes.HasPrefix(data, []byte(manifestV2Header)) {
		return nil, errManifest
	}
	data = data[len(manifestV2Header):]
	result := make([]ManifestV2Record, 0)
	identities, ids, references := map[string]bool{}, map[string]bool{}, map[string]bool{}
	account := ""
	for len(data) > 0 {
		line, rest, ok := bytes.Cut(data, []byte{'\n'})
		if !ok || len(line) > ManifestV2RecordLimit || len(result) >= ManifestV2Records {
			return nil, errManifest
		}
		var r ManifestV2Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&r) != nil || !validV2Record(r) {
			return nil, errManifest
		}
		canonical, err := json.Marshal(r)
		if err != nil || !bytes.Equal(line, canonical) {
			return nil, errManifest
		}
		identity := r.Key + "\x00" + CanonicalLabels(r.Labels)
		if identities[identity] || ids[r.ID] || references[r.Provider.Reference] || (account != "" && account != r.Provider.AccountUUID) {
			return nil, errManifest
		}
		identities[identity], ids[r.ID], references[r.Provider.Reference] = true, true, true
		account = r.Provider.AccountUUID
		result = append(result, r)
		data = rest
	}
	return result, nil
}

func EncodeManifestV2(records []ManifestV2Record, backend string) ([]byte, error) {
	data := []byte(manifestV2Header)
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil || len(line) > ManifestV2RecordLimit {
			return nil, errManifest
		}
		data = append(data, line...)
		data = append(data, '\n')
		if len(data) > ManifestV2Limit {
			return nil, errManifest
		}
	}
	if _, err := ParseManifestV2(data, backend); err != nil {
		return nil, err
	}
	return data, nil
}

// ReadManifestV2 reuses the private no-follow inventory boundary with a bounded read.
func ReadManifestV2(path, backend string) ([]ManifestV2Record, error) {
	root, err := openReadRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readManifestV2Root(root, filepath.Base(path), backend)
}
func readManifestV2Root(root *os.Root, name, backend string) ([]ManifestV2Record, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !privateMode(info) || info.Size() > ManifestV2Limit {
		return nil, errManifest
	}
	f, err := openNoFollow(root, name)
	if err != nil {
		return nil, errManifest
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || !privateMode(opened) {
		return nil, errManifest
	}
	data, err := io.ReadAll(io.LimitReader(f, ManifestV2Limit+1))
	if err != nil {
		return nil, errManifest
	}
	return ParseManifestV2(data, backend)
}

// RegisterManifestV2 adds a new binding under the existing lock. Neither identities
// nor references can be retargeted. It never creates or migrates a v1 inventory.
func RegisterManifestV2(path string, record ManifestV2Record) error {
	return registerManifestV2(path, record, atomicReplace)
}

// registerManifestV2 injects only the atomic publisher for deterministic failure tests.
func registerManifestV2(path string, record ManifestV2Record, publish func(*os.Root, string, []byte) error) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || !strings.HasSuffix(path, ".onepassword-keys") || !validV2Record(record) {
		return secure.ErrInvalidRequest
	}
	return WithWriteLock(filepath.Dir(path), func() error {
		root, err := openReadRoot(filepath.Dir(path))
		if err != nil {
			return secure.ErrTransaction
		}
		defer root.Close()
		name := filepath.Base(path)
		records, err := readManifestV2Root(root, name, "onepassword")
		if err != nil && !os.IsNotExist(err) {
			return secure.ErrTransaction
		}
		records = append(records, record)
		data, err := EncodeManifestV2(records, "onepassword")
		if err != nil {
			return secure.ErrConflict
		}
		if publish(root, name, data) != nil {
			return secure.ErrTransaction
		}
		return nil
	})
}

// ProjectManifestV2 preserves the existing metadata account meaning: a local random ID.
func ProjectManifestV2(records []ManifestV2Record) []ManifestRecord {
	result := make([]ManifestRecord, len(records))
	for i, r := range records {
		labels := make(map[string]string, len(r.Labels))
		for k, v := range r.Labels {
			labels[k] = v
		}
		result[i] = ManifestRecord{Key: r.Key, Labels: labels, Account: r.ID}
	}
	return result
}
