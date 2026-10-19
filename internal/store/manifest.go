package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/avhn/secret/internal/secure"
)

var accountID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var errManifest = errors.New("invalid or mismatched manifest")

// ManifestRecord contains only names and an opaque, stable provider account ID.
type ManifestRecord struct {
	Key     string            `json:"key"`
	Labels  map[string]string `json:"labels"`
	Account string            `json:"account"`
}

func manifestBackend(backend string) bool { return backend == "keychain" || backend == "libsecret" }
func validRecord(record ManifestRecord) bool {
	if !keyName.MatchString(record.Key) || !accountID.MatchString(record.Account) {
		return false
	}
	for n, v := range record.Labels {
		if !keyName.MatchString(n) || !labelValue.MatchString(v) {
			return false
		}
	}
	return true
}
func parseLabels(raw string) (map[string]string, bool) {
	labels := make(map[string]string)
	if raw == "" {
		return labels, true
	}
	for _, pair := range strings.Split(raw, ",") {
		n, v, ok := strings.Cut(pair, "=")
		if !ok || !keyName.MatchString(n) || !labelValue.MatchString(v) {
			return nil, false
		}
		if _, exists := labels[n]; exists {
			return nil, false
		}
		labels[n] = v
	}
	return labels, CanonicalLabels(labels) == raw
}

// ParseManifest rejects malformed inventories without ever reading provider values.
func ParseManifest(data []byte, backend string) ([]ManifestRecord, error) {
	if !manifestBackend(backend) {
		return nil, errManifest
	}
	prefix := []byte("secret-manifest-v1\nbackend=" + backend + "\n")
	if !bytes.HasPrefix(data, prefix) {
		return nil, errManifest
	}
	data = data[len(prefix):]
	identities := make(map[string]bool)
	accounts := make(map[string]bool)
	var result []ManifestRecord
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n')
		if end < 0 {
			end = len(data)
		}
		line := data[:end]
		if end == len(data) {
			data = nil
		} else {
			data = data[end+1:]
		}
		fields := bytes.Split(line, []byte{'\t'})
		if len(fields) != 3 {
			return nil, errManifest
		}
		labels, ok := parseLabels(string(fields[1]))
		record := ManifestRecord{Key: string(fields[0]), Labels: labels, Account: string(fields[2])}
		if !ok || !validRecord(record) {
			return nil, errManifest
		}
		identity := record.Key + "\x00" + string(fields[1])
		if identities[identity] || accounts[record.Account] {
			return nil, errManifest
		}
		identities[identity] = true
		accounts[record.Account] = true
		result = append(result, record)
	}
	return result, nil
}

// ReadManifest requires a private, regular inventory; missing inventories are
// represented by os.ErrNotExist so the caller can opt into creation explicitly.
func ReadManifest(path, backend string) ([]ManifestRecord, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readManifestRoot(root, filepath.Base(path), backend)
}

func readManifestRoot(root *os.Root, name, backend string) ([]ManifestRecord, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errManifest
	}
	file, err := openNoFollow(root, name)
	if err != nil {
		return nil, errors.New("cannot read manifest")
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errManifest
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, errors.New("cannot read manifest")
	}
	return ParseManifest(data, backend)
}

// UpdateManifest locks, rereads, and atomically publishes one record. It
// returns the account for an existing identity, preserving stable references.
func UpdateManifest(path, backend, key string, labels map[string]string, account string) error {
	if !manifestBackend(backend) || !validRecord(ManifestRecord{key, labels, account}) {
		return errManifest
	}
	return WithWriteLock(filepath.Dir(path), func() error {
		return UpdateManifestLocked(path, backend, key, labels, account)
	})
}

// UpdateManifestLocked publishes while the caller holds the secrets write lock.
func UpdateManifestLocked(path, backend, key string, labels map[string]string, account string) error {
	if !manifestBackend(backend) || !validRecord(ManifestRecord{key, labels, account}) {
		return errManifest
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(path)
	records, err := readManifestRoot(root, name, backend)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		records = nil
	}
	wanted := CanonicalLabels(labels)
	var out []byte
	out = append(out, []byte("secret-manifest-v1\nbackend="+backend+"\n")...)
	for _, r := range records {
		if r.Key == key && CanonicalLabels(r.Labels) == wanted {
			if r.Account != account {
				return errManifest
			}
			continue
		}
		if r.Account == account {
			return errManifest
		}
		out = append(out, []byte(r.Key+"\t"+CanonicalLabels(r.Labels)+"\t"+r.Account+"\n")...)
	}
	out = append(out, []byte(key+"\t"+wanted+"\t"+account+"\n")...)
	return atomicReplace(root, name, out)
}

// NewAccount generates an unpredictable 128-bit, lowercase hexadecimal ID.
func NewAccount() (string, error) { return newToken() }

// EncodeManifest validates a whole v1 inventory before publication. The result
// contains names only; duplicate identities or accounts are always rejected.
func EncodeManifest(records []ManifestRecord, backend string) ([]byte, error) {
	if !manifestBackend(backend) {
		return nil, secure.ErrInvalidRequest
	}
	data := []byte("secret-manifest-v1\nbackend=" + backend + "\n")
	for _, record := range records {
		if !validRecord(record) {
			return nil, secure.ErrInvalidRequest
		}
		data = append(data, []byte(record.Key+"\t"+CanonicalLabels(record.Labels)+"\t"+record.Account+"\n")...)
	}
	if _, err := ParseManifest(data, backend); err != nil {
		return nil, secure.ErrConflict
	}
	return data, nil
}

// PublishManifestLocked replaces a whole inventory. The caller must hold the
// existing secrets-directory write lock. Existing v1 single-record writers keep
// their stable-account semantics; operators explicitly use this batch publisher.
func PublishManifestLocked(path, backend string, records []ManifestRecord) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || ValidateDirectory(filepath.Dir(path)) != nil {
		return secure.ErrInvalidRequest
	}
	data, err := EncodeManifest(records, backend)
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return secure.ErrTransaction
	}
	defer root.Close()
	if err := atomicReplace(root, filepath.Base(path), data); err != nil {
		return secure.ErrTransaction
	}
	return nil
}

// RecoveryIntent records exact candidates, not an instruction to delete them.
// Compare accounts with the current manifest and verify the provider manually:
// publication and provider changes are not jointly atomic. No value backup,
// digest, equality, length or provider-wide enumeration is part of recovery.
// Version is MetadataVersion. The sibling MANIFEST.recovery is private JSON.
type RecoveryIntent struct {
	Version  int              `json:"version"`
	Backend  string           `json:"backend"`
	Prepared []ManifestRecord `json:"prepared"`
	Obsolete []ManifestRecord `json:"obsolete"`
}

const recoveryLimit = 1 << 20

func validateRecovery(intent RecoveryIntent, backend string) error {
	if intent.Version != MetadataVersion || intent.Backend != backend || !manifestBackend(backend) {
		return secure.ErrRecovery
	}
	accounts := make(map[string]bool)
	for _, records := range [][]ManifestRecord{intent.Prepared, intent.Obsolete} {
		if _, err := EncodeManifest(records, backend); err != nil {
			return secure.ErrRecovery
		}
		for _, record := range records {
			if accounts[record.Account] {
				return secure.ErrRecovery
			}
			accounts[record.Account] = true
		}
	}
	return nil
}

func readRecoveryRoot(root *os.Root, name, backend string) (RecoveryIntent, error) {
	var intent RecoveryIntent
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return intent, os.ErrNotExist
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return intent, secure.ErrRecovery
	}
	file, err := openNoFollow(root, name)
	if err != nil {
		return intent, secure.ErrRecovery
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return intent, secure.ErrRecovery
	}
	data, err := io.ReadAll(io.LimitReader(file, recoveryLimit+1))
	if err != nil || len(data) > recoveryLimit {
		return intent, secure.ErrRecovery
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return RecoveryIntent{}, secure.ErrRecovery
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || validateRecovery(intent, backend) != nil {
		return RecoveryIntent{}, secure.ErrRecovery
	}
	return intent, nil
}

// ReadRecovery reads MANIFEST.recovery without contacting a provider. Missing
// intent returns os.ErrNotExist; corrupt, aliased or insecure intent is a fixed
// recovery error. Names are tracked candidates, never proof of orphan status.
func ReadRecovery(path, backend string) (RecoveryIntent, error) {
	if runtime.GOOS == "windows" {
		return RecoveryIntent{}, secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || !manifestBackend(backend) || ValidateDirectory(filepath.Dir(path)) != nil {
		return RecoveryIntent{}, secure.ErrInvalidRequest
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if os.IsNotExist(err) {
		return RecoveryIntent{}, os.ErrNotExist
	}
	if err != nil {
		return RecoveryIntent{}, secure.ErrRecovery
	}
	defer root.Close()
	return readRecoveryRoot(root, filepath.Base(path)+".recovery", backend)
}

// ManifestEditor is valid only inside WithManifestLock's callback. It keeps
// reads, recovery intent and whole-manifest publication on one directory handle.
// Consent is the caller's prerequisite; there is no terminal bypass here.
type ManifestEditor struct {
	root      *os.Root
	name      string
	backend   string
	records   []ManifestRecord
	intent    bool
	published bool
}

// WithManifestLock uses the same lock as existing Bash-compatible writers and
// rechecks the manifest and recovery state while holding it. Pending recovery
// blocks mutation without any provider calls; it is never automatically cleared.
func WithManifestLock(path, backend string, work func(*ManifestEditor) error) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || !manifestBackend(backend) || work == nil {
		return secure.ErrInvalidRequest
	}
	err := WithWriteLock(filepath.Dir(path), func() error {
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			return secure.ErrTransaction
		}
		defer root.Close()
		name := filepath.Base(path)
		if _, err := root.Lstat(name + ".recovery"); !os.IsNotExist(err) {
			return secure.ErrRecovery
		}
		records, err := readManifestRoot(root, name, backend)
		if err != nil && !os.IsNotExist(err) {
			return secure.ErrTransaction
		}
		editor := &ManifestEditor{root: root, name: name, backend: backend, records: records}
		defer func() { editor.root = nil }()
		err = work(editor)
		if editor.intent {
			return secure.ErrRecovery
		}
		return err
	})
	return mutationError(err)
}

// Records returns independently owned names-only records from the locked read.
func (editor *ManifestEditor) Records() []ManifestRecord {
	result := make([]ManifestRecord, len(editor.records))
	for i, record := range editor.records {
		labels := make(map[string]string, len(record.Labels))
		for name, value := range record.Labels {
			labels[name] = value
		}
		result[i] = ManifestRecord{Key: record.Key, Labels: labels, Account: record.Account}
	}
	return result
}

// PersistRecovery must succeed before the first provider mutation. It never
// overwrites previous recovery. A crash leaves this names-only intent in place.
func (editor *ManifestEditor) PersistRecovery(intent RecoveryIntent) error {
	if editor.root == nil || editor.intent || validateRecovery(intent, editor.backend) != nil {
		return secure.ErrRecovery
	}
	if _, err := editor.root.Lstat(editor.name + ".recovery"); !os.IsNotExist(err) {
		return secure.ErrRecovery
	}
	data, err := json.Marshal(intent)
	if err != nil || len(data) > recoveryLimit {
		return secure.ErrRecovery
	}
	if err := atomicReplace(editor.root, editor.name+".recovery", data); err != nil {
		return secure.ErrRecovery
	}
	editor.intent = true
	return syncManifestDirectory(editor.root)
}

// Publish atomically replaces the whole manifest on the anchored directory.
func (editor *ManifestEditor) Publish(records []ManifestRecord) error {
	if editor.root == nil || !editor.intent {
		return secure.ErrRecovery
	}
	data, err := EncodeManifest(records, editor.backend)
	if err != nil {
		return err
	}
	if err := atomicReplace(editor.root, editor.name, data); err != nil {
		return secure.ErrTransaction
	}
	if err := syncManifestDirectory(editor.root); err != nil {
		return err
	}
	editor.published = true
	return nil
}

// ClearRecovery is called only after publication and exact-account cleanup.
// It never repairs a killed writer or a failed transaction automatically.
func (editor *ManifestEditor) ClearRecovery() error {
	if editor.root == nil || !editor.intent || !editor.published {
		return secure.ErrRecovery
	}
	if _, err := readRecoveryRoot(editor.root, editor.name+".recovery", editor.backend); err != nil {
		return secure.ErrRecovery
	}
	if err := editor.root.Remove(editor.name + ".recovery"); err != nil {
		return secure.ErrRecovery
	}
	if err := syncManifestDirectory(editor.root); err != nil {
		return err
	}
	editor.intent = false
	return nil
}

func syncManifestDirectory(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return secure.ErrRecovery
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return secure.ErrRecovery
	}
	return nil
}
