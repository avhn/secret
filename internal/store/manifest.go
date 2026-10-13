package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var accountID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var errManifest = errors.New("invalid or mismatched manifest")

// ManifestRecord contains only names and an opaque, stable provider account ID.
type ManifestRecord struct {
	Key     string
	Labels  map[string]string
	Account string
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
