package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
)

const (
	AgeMagic        = "secret-age-store-v1\n"
	agePayloadMagic = "secret-age-payload-v1\n"
	MaxAgeMetadata  = 1 << 20
	MaxAgeFile      = 18 << 20
	MaxAgePlaintext = 16 << 20
	MaxAgeRecords   = 1024
)

var (
	ErrAge           = errors.New("invalid or unauthenticated age store")
	ErrAgeDurability = errors.New("age store published; durability uncertain, verify manually")
)

// AgeEnvelope contains public, unauthenticated metadata and borrowed ciphertext.
// Metadata must never authorize a value read or mutation.
type AgeEnvelope struct {
	Recipients []string
	Records    []ManifestRecord
	Prefix     []byte
	Ciphertext []byte
}

func ageU32(out []byte, n int) []byte  { return binary.BigEndian.AppendUint32(out, uint32(n)) }
func ageField(out, data []byte) []byte { return append(ageU32(out, len(data)), data...) }
func takeAgeField(data *[]byte, limit int) ([]byte, bool) {
	if len(*data) < 4 {
		return nil, false
	}
	n := uint64(binary.BigEndian.Uint32((*data)[:4]))
	*data = (*data)[4:]
	if n > uint64(limit) || n > uint64(len(*data)) {
		return nil, false
	}
	field := (*data)[:int(n)]
	*data = (*data)[int(n):]
	return field, true
}

// CanonicalAgeRecipients delegates X25519 syntax and checksum validation to age.
func CanonicalAgeRecipients(recipients []string) ([]string, error) {
	if len(recipients) == 0 || len(recipients) > 32 {
		return nil, ErrAge
	}
	result := append([]string(nil), recipients...)
	for _, text := range result {
		r, err := age.ParseX25519Recipient(text)
		if err != nil || r.String() != text {
			return nil, ErrAge
		}
	}
	sort.Strings(result)
	for i := 1; i < len(result); i++ {
		if result[i] == result[i-1] {
			return nil, ErrAge
		}
	}
	return result, nil
}

func EncodeAgePrefix(recipients []string, records []ManifestRecord) ([]byte, error) {
	recipients, err := CanonicalAgeRecipients(recipients)
	if err != nil || len(records) > MaxAgeRecords {
		return nil, ErrAge
	}
	manifest, err := EncodeManifest(records, "age")
	if err != nil {
		return nil, ErrAge
	}
	metadata := ageU32(nil, len(recipients))
	for _, recipient := range recipients {
		metadata = ageField(metadata, []byte(recipient))
	}
	metadata = ageField(metadata, manifest)
	if len(metadata) > MaxAgeMetadata {
		return nil, ErrAge
	}
	return append(ageU32([]byte(AgeMagic), len(metadata)), metadata...), nil
}

// ParseAgeEnvelope is bounded and does not authenticate metadata or decrypt.
func ParseAgeEnvelope(data []byte) (AgeEnvelope, error) {
	var result AgeEnvelope
	if len(data) > MaxAgeFile || !bytes.HasPrefix(data, []byte(AgeMagic)) {
		return result, ErrAge
	}
	rest := data[len(AgeMagic):]
	metadata, ok := takeAgeField(&rest, MaxAgeMetadata)
	if !ok || len(metadata) < 4 || !bytes.HasPrefix(rest, []byte("age-encryption.org/v1\n")) {
		return result, ErrAge
	}
	result.Prefix = data[:len(data)-len(rest)]
	result.Ciphertext = rest
	count := binary.BigEndian.Uint32(metadata[:4])
	metadata = metadata[4:]
	if count == 0 || count > 32 {
		return AgeEnvelope{}, ErrAge
	}
	for i := uint32(0); i < count; i++ {
		text, ok := takeAgeField(&metadata, 128)
		if !ok {
			return AgeEnvelope{}, ErrAge
		}
		result.Recipients = append(result.Recipients, string(text))
	}
	canonical, err := CanonicalAgeRecipients(result.Recipients)
	if err != nil {
		return AgeEnvelope{}, ErrAge
	}
	for i := range canonical {
		if canonical[i] != result.Recipients[i] {
			return AgeEnvelope{}, ErrAge
		}
	}
	manifest, ok := takeAgeField(&metadata, MaxAgeMetadata)
	if !ok || len(metadata) != 0 {
		return AgeEnvelope{}, ErrAge
	}
	result.Records, err = ParseManifest(manifest, "age")
	if err != nil || len(result.Records) > MaxAgeRecords {
		return AgeEnvelope{}, ErrAge
	}
	encoded, err := EncodeManifest(result.Records, "age")
	if err != nil || !bytes.Equal(manifest, encoded) {
		return AgeEnvelope{}, ErrAge
	}
	return result, nil
}

// ValidateAgePlaintext rejects warnings, duplicate identities and inventory drift.
func ValidateAgePlaintext(dotenv []byte, manifest []ManifestRecord) error {
	if len(dotenv) > MaxAgePlaintext || len(manifest) > MaxAgeRecords {
		return ErrAge
	}
	records, warnings := ParseMetadata(dotenv)
	if len(warnings) != 0 || len(records) != len(manifest) {
		return ErrAge
	}
	seen := make(map[string]bool)
	for i, record := range records {
		identity := record.Key + "\x00" + CanonicalLabels(record.Labels)
		if seen[identity] || record.Key != manifest[i].Key || CanonicalLabels(record.Labels) != CanonicalLabels(manifest[i].Labels) {
			return ErrAge
		}
		seen[identity] = true
	}
	return nil
}

// EncodeAgePayload returns owned plaintext. Callers must clear it on every path.
func EncodeAgePayload(prefix, dotenv []byte, records []ManifestRecord) ([]byte, error) {
	if ValidateAgePlaintext(dotenv, records) != nil {
		return nil, ErrAge
	}
	hash := sha256.Sum256(prefix)
	out := make([]byte, 0, len(agePayloadMagic)+32+4+len(dotenv))
	out = append(out, agePayloadMagic...)
	out = append(out, hash[:]...)
	return ageField(out, dotenv), nil
}

// DecodeAgePayload verifies binding before returning independently owned bytes.
func DecodeAgePayload(envelope AgeEnvelope, payload []byte) ([]byte, error) {
	if !bytes.HasPrefix(payload, []byte(agePayloadMagic)) {
		return nil, ErrAge
	}
	payload = payload[len(agePayloadMagic):]
	hash := sha256.Sum256(envelope.Prefix)
	if len(payload) < 32 || !bytes.Equal(payload[:32], hash[:]) {
		return nil, ErrAge
	}
	payload = payload[32:]
	dotenv, ok := takeAgeField(&payload, MaxAgePlaintext)
	if !ok || len(payload) != 0 || ValidateAgePlaintext(dotenv, envelope.Records) != nil {
		return nil, ErrAge
	}
	return secure.Clone(dotenv), nil
}

// AgePath accepts only explicit age references; default discovery is unchanged.
func AgePath(directory, reference string) (string, error) {
	kind, name, ok := strings.Cut(reference, ":")
	if !ok || kind != "age" || !backendName.MatchString(name) || !filepath.IsAbs(directory) {
		return "", ErrAge
	}
	return filepath.Join(directory, name+".secret.age"), nil
}

// OpenPrivateDirectory rejects aliases on every component, anchoring each walk.
// Ancestors may be shared; the requested directory must be private and owned.
func OpenPrivateDirectory(path string) (*os.Root, error) { return openPrivateAgeDirectory(path, false) }

func openPrivateAgeDirectory(path string, create bool) (*os.Root, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrAge
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, ErrAge
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			root.Close()
			return nil, ErrAge
		}
		info, e := root.Lstat(component)
		if os.IsNotExist(e) && create {
			if e = root.Mkdir(component, 0700); e == nil {
				info, e = root.Lstat(component)
			}
		}
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, ErrAge
		}
		next, e := root.OpenRoot(component)
		root.Close()
		if e != nil {
			return nil, ErrAge
		}
		opened, e := next.Stat(".")
		if e != nil || !os.SameFile(info, opened) {
			next.Close()
			return nil, ErrAge
		}
		root = next
	}
	info, err := root.Stat(".")
	if err != nil || !privateAgeInfo(info, true) {
		root.Close()
		return nil, ErrAge
	}
	return root, nil
}

func readAgePrivate(root *os.Root, name string, limit int) ([]byte, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	if err != nil || !privateAgeInfo(info, false) || info.Size() > int64(limit) {
		return nil, ErrAge
	}
	file, err := openNoFollow(root, name)
	if err != nil {
		return nil, ErrAge
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !privateAgeInfo(opened, false) || !os.SameFile(info, opened) {
		return nil, ErrAge
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		secure.Clear(data)
		return nil, ErrAge
	}
	return data, nil
}

// ReadPrivateAgeFile is shared by encrypted envelopes and protected key files.
func ReadPrivateAgeFile(path string, limit int) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	if limit <= 0 || limit > MaxAgeFile {
		return nil, ErrAge
	}
	root, err := OpenPrivateDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readAgePrivate(root, filepath.Base(path), limit)
}

func ReadAgeEnvelope(path string) (AgeEnvelope, error) {
	data, err := ReadPrivateAgeFile(path, MaxAgeFile)
	if err != nil {
		return AgeEnvelope{}, ErrAge
	}
	return ParseAgeEnvelope(data)
}

// AgeEditor is synchronous and valid only inside WithAgeLock. Only complete
// ciphertext envelopes may be published; plaintext never reaches scratch.
type AgeEditor struct {
	root       *os.Root
	name       string
	existing   []byte
	create     bool
	checkpoint func(string) error
}

func (editor *AgeEditor) Existing() []byte { return editor.existing }
func (editor *AgeEditor) Publish(ciphertext []byte) error {
	if editor.root == nil {
		return ErrAge
	}
	if _, err := ParseAgeEnvelope(ciphertext); err != nil {
		return err
	}
	return atomicReplaceChecked(editor.root, editor.name, ciphertext, true, editor.checkpoint)
}

func WithAgeLock(path string, create bool, work func(*AgeEditor) error) error {
	return withAgeLock(path, create, work, nil)
}
func withAgeLock(path string, create bool, work func(*AgeEditor) error, checkpoint func(string) error) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(path) || work == nil {
		return ErrAge
	}
	root, err := OpenPrivateDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return withRootLock(root, lockWait, func(root *os.Root) error {
		name := filepath.Base(path)
		// Create-only checks presence before opening any existing target.
		if create {
			if _, e := root.Lstat(name); !os.IsNotExist(e) {
				return secure.ErrConflict
			}
		}
		data, e := readAgePrivate(root, name, MaxAgeFile)
		if create {
			if !os.IsNotExist(e) {
				return ErrAge
			}
		} else if e != nil {
			return ErrAge
		}
		editor := &AgeEditor{root: root, name: name, existing: data, create: create, checkpoint: checkpoint}
		defer func() { editor.root = nil }()
		return work(editor)
	})
}

// ReadAgeKeyFile confines keys to the private HOME/.secrets/.age-keys namespace.
// Every private descendant is checked and opened through the previous handle.
func ReadAgeKeyFile(home, path string, limit int) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	if !filepath.IsAbs(home) || !filepath.IsAbs(path) || filepath.Clean(path) != path || limit <= 0 || limit > 64<<10 {
		return nil, ErrAge
	}
	base := filepath.Join(home, ".secrets")
	relative, err := filepath.Rel(base, path)
	if err != nil || !strings.HasPrefix(relative, ".age-keys"+string(filepath.Separator)) {
		return nil, ErrAge
	}
	root, err := OpenPrivateDirectory(base)
	if err != nil {
		return nil, ErrAge
	}
	components := strings.Split(relative, string(filepath.Separator))
	for _, component := range components[:len(components)-1] {
		if component == "" || component == "." || component == ".." {
			root.Close()
			return nil, ErrAge
		}
		info, err := root.Lstat(component)
		if err != nil || !privateAgeInfo(info, true) {
			root.Close()
			return nil, ErrAge
		}
		next, err := root.OpenRoot(component)
		root.Close()
		if err != nil {
			return nil, ErrAge
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(info, opened) || !privateAgeInfo(opened, true) {
			next.Close()
			return nil, ErrAge
		}
		root = next
	}
	defer root.Close()
	return readAgePrivate(root, components[len(components)-1], limit)
}

// InitializeAgeDirectories is called only after exact operator confirmation.
// Existing directories are checked, never silently chmodded.
func InitializeAgeDirectories(home, directory string) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	for _, path := range []string{filepath.Join(home, ".secrets"), filepath.Join(home, ".secrets", ".age-keys"), directory} {
		root, err := openPrivateAgeDirectory(path, true)
		if err != nil {
			return ErrAge
		}
		root.Close()
	}
	return nil
}

// IsAgeStoreBytes prevents an envelope, including an unknown version, from
// being silently parsed as an empty plaintext store.
func IsAgeStoreBytes(data []byte) bool { return bytes.HasPrefix(data, []byte("secret-age-store-")) }
