package backend

import (
	"bytes"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const maxAgeKeyFile = 64 << 10

// AgeConfig has explicit identity selection only. Identity paths are never
// serialized into store metadata, audit, MCP configuration or error messages.
type AgeConfig struct{ Home, SecretsDir, IdentityFile string }

// AgeSnapshot owns all decrypted bytes until Close. Library identity copies are
// outside application cleanup: age takes strings and exposes no wiping API.
type AgeSnapshot struct {
	Envelope store.AgeEnvelope
	Dotenv   []byte
	Records  []store.Record
}

func (snapshot *AgeSnapshot) Close() {
	secure.Clear(snapshot.Dotenv)
	snapshot.Dotenv = nil
	for i := range snapshot.Records {
		secure.Clear(snapshot.Records[i].Value)
		snapshot.Records[i].Value = nil
	}
	snapshot.Records = nil
}

// parseAgeKeyLines borrows protected file bytes without converting whole files or
// identity lines to application-owned strings. Only the age parser gets a string.
func parseAgeKeyLines(data []byte, identity bool) ([]age.Identity, []string, error) {
	if len(data) > maxAgeKeyFile {
		return nil, nil, store.ErrAge
	}
	var identities []age.Identity
	var recipients []string
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
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if len(recipients) == 32 {
			return nil, nil, store.ErrAge
		}
		if identity {
			id, err := age.ParseX25519Identity(string(line))
			if err != nil {
				return nil, nil, store.ErrAge
			}
			recipient := id.Recipient().String()
			for _, previous := range recipients {
				if previous == recipient {
					return nil, nil, store.ErrAge
				}
			}
			identities = append(identities, id)
			recipients = append(recipients, recipient)
		} else {
			// Recipients are public names; validation is delegated to age below.
			recipients = append(recipients, string(line))
		}
	}
	canonical, err := store.CanonicalAgeRecipients(recipients)
	if err != nil {
		return nil, nil, store.ErrAge
	}
	return identities, canonical, nil
}
func (config AgeConfig) keyFile(path string, identity bool) ([]age.Identity, []string, error) {
	data, err := store.ReadAgeKeyFile(config.Home, path, maxAgeKeyFile)
	defer secure.Clear(data)
	if err != nil {
		return nil, nil, store.ErrAge
	}
	return parseAgeKeyLines(data, identity)
}
func (config AgeConfig) recipients(path string) ([]string, error) {
	_, recipients, err := config.keyFile(path, false)
	return recipients, err
}

// checkAgeStanzas rejects every non-X25519 mode before age performs key work.
// Native X25519 has one 43-byte argument and one 43-byte short body line.
// Header work is bounded to 32 stanzas and 8 KiB, independently of
// the library's wider format limits. age remains the authoritative parser.
func checkAgeStanzas(ciphertext []byte, count int) error {
	if count < 1 || count > 32 || !bytes.HasPrefix(ciphertext, []byte("age-encryption.org/v1\n")) {
		return store.ErrAge
	}
	rest := ciphertext[len("age-encryption.org/v1\n"):]
	consumed := 0
	line := func() ([]byte, bool) {
		n := bytes.IndexByte(rest, '\n')
		if n < 0 || n > 128 || consumed+n+1 > 8192 {
			return nil, false
		}
		out := rest[:n]
		rest = rest[n+1:]
		consumed += n + 1
		return out, true
	}
	for i := 0; i < count; i++ {
		header, ok := line()
		if !ok || !bytes.HasPrefix(header, []byte("-> X25519 ")) || len(header) != len("-> X25519 ")+43 {
			return store.ErrAge
		}
		body, ok := line()
		if !ok || len(body) != 43 {
			return store.ErrAge
		}
	}
	footer, ok := line()
	if !ok || !bytes.HasPrefix(footer, []byte("--- ")) || len(footer) != 47 {
		return store.ErrAge
	}
	return nil
}

func decryptAge(data []byte, identities []age.Identity) (*AgeSnapshot, error) {
	envelope, err := store.ParseAgeEnvelope(data)
	if err != nil || checkAgeStanzas(envelope.Ciphertext, len(envelope.Recipients)) != nil || len(identities) == 0 || len(identities) > 32 {
		return nil, store.ErrAge
	}
	reader, err := age.Decrypt(bytes.NewReader(envelope.Ciphertext), identities...)
	if err != nil {
		return nil, store.ErrAge
	}
	// A bounded read is followed by a successful authenticated EOF, not a prefix
	// selection. Over-limit plaintext never reaches the dotenv parser.
	payload, err := io.ReadAll(io.LimitReader(reader, store.MaxAgePlaintext+128))
	defer secure.Clear(payload)
	if err != nil || len(payload) > store.MaxAgePlaintext+len("secret-age-payload-v1\n")+36 {
		return nil, store.ErrAge
	}
	var extra [1]byte
	n, end := reader.Read(extra[:])
	secure.Clear(extra[:])
	if n != 0 || end != io.EOF {
		return nil, store.ErrAge
	}
	dotenv, err := store.DecodeAgePayload(envelope, payload)
	if err != nil {
		return nil, store.ErrAge
	}
	records, warnings := store.Parse(dotenv)
	if len(warnings) != 0 {
		secure.Clear(dotenv)
		for _, r := range records {
			secure.Clear(r.Value)
		}
		return nil, store.ErrAge
	}
	return &AgeSnapshot{Envelope: envelope, Dotenv: dotenv, Records: records}, nil
}

func (config AgeConfig) Read(reference string) (*AgeSnapshot, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	path, err := store.AgePath(config.SecretsDir, reference)
	if err != nil {
		return nil, store.ErrAge
	}
	data, err := store.ReadPrivateAgeFile(path, store.MaxAgeFile)
	if err != nil {
		return nil, store.ErrAge
	}
	identities, _, err := config.keyFile(config.IdentityFile, true)
	if err != nil {
		return nil, store.ErrAge
	}
	return decryptAge(data, identities)
}

type ageSteps struct{ checkpoint func(string) error }

func (steps ageSteps) check(phase string) error {
	if steps.checkpoint != nil {
		return steps.checkpoint(phase)
	}
	return nil
}
func encryptAge(dotenv []byte, records []store.ManifestRecord, recipients []string, identities []age.Identity, steps ageSteps) ([]byte, error) {
	prefix, err := store.EncodeAgePrefix(recipients, records)
	if err != nil {
		return nil, store.ErrAge
	}
	payload, err := store.EncodeAgePayload(prefix, dotenv, records)
	if err != nil {
		return nil, store.ErrAge
	}
	defer secure.Clear(payload)
	parsed := make([]age.Recipient, 0, len(recipients))
	for _, text := range recipients {
		r, err := age.ParseX25519Recipient(text)
		if err != nil {
			return nil, store.ErrAge
		}
		parsed = append(parsed, r)
	}
	var buffer bytes.Buffer
	buffer.Write(prefix)
	writer, err := age.Encrypt(&buffer, parsed...)
	if err != nil {
		return nil, store.ErrAge
	}
	if _, err = writer.Write(payload); err != nil {
		return nil, store.ErrAge
	}
	if steps.check("encrypt-close") != nil {
		return nil, store.ErrAge
	}
	if writer.Close() != nil || buffer.Len() > store.MaxAgeFile {
		return nil, store.ErrAge
	}
	if steps.check("candidate-verify") != nil {
		return nil, store.ErrAge
	}
	candidate, err := decryptAge(buffer.Bytes(), identities)
	if err != nil {
		return nil, store.ErrAge
	}
	defer candidate.Close()
	if !bytes.Equal(candidate.Dotenv, dotenv) {
		return nil, store.ErrAge
	}
	return buffer.Bytes(), nil
}

// Init is create-only under the same anchored lock as ordinary writes. Existing
// targets are rejected before decrypting or opening their bytes.
func (config AgeConfig) Init(reference, recipientsFile string) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	path, err := store.AgePath(config.SecretsDir, reference)
	if err != nil {
		return store.ErrAge
	}
	return store.WithAgeLock(path, true, func(editor *store.AgeEditor) error {
		identities, _, err := config.keyFile(config.IdentityFile, true)
		if err != nil {
			return store.ErrAge
		}
		recipients, err := config.recipients(recipientsFile)
		if err != nil {
			return store.ErrAge
		}
		candidate, err := encryptAge(nil, nil, recipients, identities, ageSteps{})
		if err != nil {
			return err
		}
		return editor.Publish(candidate)
	})
}
func (config AgeConfig) Rekey(reference, recipientsFile, newIdentityFile string) error {
	return config.rekey(reference, recipientsFile, newIdentityFile, ageSteps{})
}
func (config AgeConfig) rekey(reference, recipientsFile, newIdentityFile string, steps ageSteps) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	path, err := store.AgePath(config.SecretsDir, reference)
	if err != nil {
		return store.ErrAge
	}
	return store.WithAgeLock(path, false, func(editor *store.AgeEditor) error {
		identities, _, err := config.keyFile(config.IdentityFile, true)
		if err != nil {
			return store.ErrAge
		}
		snapshot, err := decryptAge(editor.Existing(), identities)
		if err != nil {
			return err
		}
		defer snapshot.Close()
		recipients, err := config.recipients(recipientsFile)
		if err != nil {
			return store.ErrAge
		}
		newIdentities, _, err := config.keyFile(newIdentityFile, true)
		if err != nil {
			return store.ErrAge
		}
		candidate, err := encryptAge(snapshot.Dotenv, snapshot.Envelope.Records, recipients, newIdentities, steps)
		if err != nil {
			return err
		}
		return editor.Publish(candidate)
	})
}

// AgeTransaction rereads, authenticates, checks and publishes the whole store.
// Recipients and stable accounts come only from the authenticated snapshot.
type AgeTransaction struct {
	Config                          AgeConfig
	Reference                       string
	FailOnConflict, RequireExisting bool
}

var _ store.Transaction = AgeTransaction{}

func (transaction AgeTransaction) Apply(mutations []store.Mutation) error {
	return transaction.apply(mutations, ageSteps{})
}
func (transaction AgeTransaction) apply(mutations []store.Mutation, steps ageSteps) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if store.ValidateMutations(mutations) != nil || (transaction.FailOnConflict && transaction.RequireExisting) {
		return secure.ErrInvalidRequest
	}
	path, err := store.AgePath(transaction.Config.SecretsDir, transaction.Reference)
	if err != nil {
		return store.ErrAge
	}
	return store.WithAgeLock(path, false, func(editor *store.AgeEditor) error {
		identities, _, err := transaction.Config.keyFile(transaction.Config.IdentityFile, true)
		if err != nil {
			return store.ErrAge
		}
		snapshot, err := decryptAge(editor.Existing(), identities)
		if err != nil {
			return err
		}
		defer snapshot.Close()
		metadata, _ := store.ParseMetadata(snapshot.Dotenv)
		if err := store.CheckMutationConflicts(metadata, mutations, transaction.FailOnConflict, transaction.RequireExisting); err != nil {
			return err
		}
		dotenv, err := store.MutateBytes(snapshot.Dotenv, mutations)
		if err != nil {
			return err
		}
		defer secure.Clear(dotenv)
		records, err := ageMutatedInventory(snapshot.Envelope.Records, dotenv, mutations)
		if err != nil {
			return err
		}
		candidate, err := encryptAge(dotenv, records, snapshot.Envelope.Recipients, identities, steps)
		if err != nil {
			return err
		}
		return editor.Publish(candidate)
	})
}
func ageMutatedInventory(previous []store.ManifestRecord, dotenv []byte, mutations []store.Mutation) ([]store.ManifestRecord, error) {
	accounts := make(map[string]string)
	used := make(map[string]bool)
	for _, record := range previous {
		accounts[record.Key+"\x00"+store.CanonicalLabels(record.Labels)] = record.Account
		used[record.Account] = true
	}
	for _, mutation := range mutations {
		if mutation.Kind == store.MutationRename {
			labels := "\x00" + store.CanonicalLabels(mutation.Labels)
			accounts[mutation.NewKey+labels] = accounts[mutation.Key+labels]
		}
	}
	metadata, _ := store.ParseMetadata(dotenv)
	var records []store.ManifestRecord
	for _, record := range metadata {
		identity := record.Key + "\x00" + store.CanonicalLabels(record.Labels)
		account := accounts[identity]
		if account == "" {
			var err error
			account, err = freshAccount(used, store.NewAccount)
			if err != nil {
				return nil, err
			}
		}
		records = append(records, store.ManifestRecord{Key: record.Key, Labels: record.Labels, Account: account})
	}
	if store.ValidateAgePlaintext(dotenv, records) != nil {
		return nil, store.ErrAge
	}
	return records, nil
}

// ValidateAgeIdentityPath is syntax-only and safe before consent. Existence,
// ownership and permissions are checked only by the anchored reader after it.
func ValidateAgeIdentityPath(home, path string) bool {
	if !filepath.IsAbs(home) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	namespace := filepath.Join(home, ".secrets", ".age-keys")
	relative, err := filepath.Rel(namespace, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
