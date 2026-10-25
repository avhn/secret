package store

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/avhn/secret/internal/secure"
)

// ValidateMutations checks an independent batch before any store or provider
// access. An identity may occur only once, including rename destinations. Values
// are borrowed, validated privately and never retained.
func ValidateMutations(mutations []Mutation) error {
	return validateMutationIdentities(mutations, true)
}

func validateMutationIdentities(mutations []Mutation, validateValues bool) error {
	if len(mutations) == 0 {
		return secure.ErrInvalidRequest
	}
	seen := make(map[string]bool)
	for _, mutation := range mutations {
		if ValidateIdentity(mutation.Key, mutation.Labels) != nil {
			return secure.ErrInvalidRequest
		}
		identity := mutation.Key + "\x00" + CanonicalLabels(mutation.Labels)
		if seen[identity] {
			return secure.ErrConflict
		}
		seen[identity] = true
		switch mutation.Kind {
		case MutationPut:
			if mutation.NewKey != "" {
				return secure.ErrInvalidRequest
			}
			if validateValues {
				normalized, err := NormalizeValue(mutation.Value)
				secure.Clear(normalized)
				if err != nil {
					return secure.ErrInvalidRequest
				}
			}
		case MutationDelete, MutationRename:
			if len(mutation.Value) != 0 {
				return secure.ErrInvalidRequest
			}
			if mutation.Kind == MutationDelete {
				if mutation.NewKey != "" {
					return secure.ErrInvalidRequest
				}
				continue
			}
			if ValidateIdentity(mutation.NewKey, mutation.Labels) != nil {
				return secure.ErrInvalidRequest
			}
			identity = mutation.NewKey + "\x00" + CanonicalLabels(mutation.Labels)
			if seen[identity] {
				return secure.ErrConflict
			}
			seen[identity] = true
		default:
			return secure.ErrInvalidRequest
		}
	}
	return nil
}

// CheckMutationConflicts performs names-only exact-identity preflight. Put may
// replace an identity unless failOnConflict is set (import/export use true).
// Delete and rename require an existing source; rename never replaces a peer.
// requireExisting also requires put sources (rotation). Values are not inspected:
// callers may preflight nil put values before fetching any provider bytes. Apply
// separately validates values. Call again under the lock after preflight.
func CheckMutationConflicts(records []MetadataRecord, mutations []Mutation, failOnConflict, requireExisting bool) error {
	if failOnConflict && requireExisting {
		return secure.ErrInvalidRequest
	}
	if err := validateMutationIdentities(mutations, false); err != nil {
		return err
	}
	identities := make(map[string]bool)
	for _, record := range records {
		identities[record.Key+"\x00"+CanonicalLabels(record.Labels)] = true
	}
	for _, mutation := range mutations {
		labels := "\x00" + CanonicalLabels(mutation.Labels)
		exists := identities[mutation.Key+labels]
		if mutation.Kind == MutationPut {
			if failOnConflict && exists {
				return secure.ErrConflict
			}
			if requireExisting && !exists {
				return secure.ErrNotFound
			}
		} else {
			if !exists {
				return secure.ErrNotFound
			}
			if mutation.Kind == MutationRename && identities[mutation.NewKey+labels] {
				return secure.ErrConflict
			}
		}
	}
	return nil
}

// FileTransaction publishes one formatting-preserving batch. Path and SecretsDir
// must be absolute; SecretsDir is the existing Bash-compatible lock namespace,
// including for files outside that directory. The CLI must obtain consent first.
// FailOnConflict is the mandatory insert-only policy for import/export, not a
// consent bypass. RequireExisting makes put replace-only for rotation. These
// policies are mutually exclusive. Windows rejects before side effects until M5a.
type FileTransaction struct {
	SecretsDir      string
	Path            string
	FailOnConflict  bool
	RequireExisting bool
}

var _ Transaction = FileTransaction{}

func (transaction FileTransaction) Apply(mutations []Mutation) error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(transaction.Path) || !filepath.IsAbs(transaction.SecretsDir) || (transaction.FailOnConflict && transaction.RequireExisting) {
		return secure.ErrInvalidRequest
	}
	if err := ValidateMutations(mutations); err != nil {
		return err
	}
	err := WithWriteLock(transaction.SecretsDir, func() error {
		dir := filepath.Dir(transaction.Path)
		if ValidateDirectory(dir) != nil {
			return secure.ErrTransaction
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return secure.ErrTransaction
		}
		if ValidateDirectory(dir) != nil {
			return secure.ErrTransaction
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			return secure.ErrTransaction
		}
		defer root.Close()
		name := filepath.Base(transaction.Path)
		source, err := readRegular(root, name)
		defer secure.Clear(source)
		if err != nil && !os.IsNotExist(err) {
			return secure.ErrTransaction
		}
		if IsAgeStoreBytes(source) {
			return secure.ErrInvalidRequest
		}
		records, _ := ParseMetadata(source)
		if err := CheckMutationConflicts(records, mutations, transaction.FailOnConflict, transaction.RequireExisting); err != nil {
			return err
		}
		result, err := MutateBytes(source, mutations)
		defer secure.Clear(result)
		if err != nil {
			return err
		}
		if err := atomicReplace(root, name, result); err != nil {
			return secure.ErrTransaction
		}
		return nil
	})
	return mutationError(err)
}

func mutationError(err error) error {
	switch err {
	case nil, secure.ErrConflict, secure.ErrNotFound, secure.ErrInvalidRequest, secure.ErrRecovery, secure.ErrUnsupported:
		return err
	default:
		return secure.ErrTransaction
	}
}

// rewriteMutation uses parser line identities so malformed assignments and peer
// bytes stay untouched. Replacement keeps indentation, export and line endings;
// put collapses duplicate identities at their last occurrence, like last-wins
// selection. Rename preserves the original value spelling, including quotes.
func rewriteMutation(source []byte, mutation Mutation) ([]byte, error) {
	records, _ := ParseMetadata(source)
	wanted := CanonicalLabels(mutation.Labels)
	matches := make(map[int]bool)
	last := 0
	for _, record := range records {
		if record.Key == mutation.Key && CanonicalLabels(record.Labels) == wanted {
			matches[record.Line] = true
			last = record.Line
		}
	}
	var encoded []byte
	if mutation.Kind == MutationPut {
		value, err := NormalizeValue(mutation.Value)
		if err != nil {
			return nil, secure.ErrInvalidRequest
		}
		defer secure.Clear(value)
		encoded = make([]byte, 0, len(value)+2)
		if value[0] == '\'' || value[0] == '"' || value[len(value)-1] == '\'' || value[len(value)-1] == '"' {
			encoded = append(encoded, '\'')
			encoded = append(encoded, value...)
			encoded = append(encoded, '\'')
		} else {
			encoded = append(encoded, value...)
		}
		defer secure.Clear(encoded)
		if last == 0 {
			line := make([]byte, 0, len(mutation.Key)+len(encoded)+2)
			line = append(line, mutation.Key...)
			line = append(line, '=')
			line = append(line, encoded...)
			line = append(line, '\n')
			defer secure.Clear(line)
			return insertMutation(source, wanted, line), nil
		}
	}
	result := make([]byte, 0, len(source)+len(encoded)+len(matches)*len(mutation.NewKey))
	for i, line := range splitLines(source) {
		if !matches[i+1] {
			result = append(result, line...)
			continue
		}
		if mutation.Kind == MutationDelete || (mutation.Kind == MutationPut && i+1 != last) {
			continue
		}
		indices := assignment.FindSubmatchIndex(contentLine(line))
		if mutation.Kind == MutationRename {
			result = append(result, line[:indices[2]]...)
			result = append(result, mutation.NewKey...)
			result = append(result, line[indices[3]:]...)
		} else {
			result = append(result, line[:indices[4]]...)
			result = append(result, encoded...)
			// CRLF and absent final LF are part of the unaffected framing.
			result = append(result, line[len(contentLine(line)):]...)
		}
	}
	return result, nil
}

// insertMutation inserts into the last matching scope, or appends a new one.
// It owns only the returned allocation; line and source remain borrowed.
func insertMutation(source []byte, wanted string, line []byte) []byte {
	at, offset := -1, 0
	scope := ""
	if wanted == "" {
		at = 0
	}
	for _, existing := range splitLines(source) {
		if next, ok := validHeader(contentLine(existing)); ok {
			scope = next
		}
		offset += len(existing)
		if scope == wanted {
			at = offset
		}
	}
	result := make([]byte, 0, len(source)+len(line)+len(wanted)+4)
	if at < 0 {
		result = append(result, source...)
		if len(result) > 0 && result[len(result)-1] != '\n' {
			result = append(result, '\n')
		}
		result = append(result, '[')
		result = append(result, wanted...)
		result = append(result, ']', '\n')
		return append(result, line...)
	}
	result = append(result, source[:at]...)
	if len(result) > 0 && result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	result = append(result, line...)
	return append(result, source[at:]...)
}

// MutateBytes applies a synchronous byte batch without filesystem access. It
// returns owned bytes; source and mutations remain borrowed and unchanged.
func MutateBytes(source []byte, mutations []Mutation) ([]byte, error) {
	if err := ValidateMutations(mutations); err != nil {
		return nil, err
	}
	result := secure.Clone(source)
	for _, mutation := range mutations {
		next, err := rewriteMutation(result, mutation)
		secure.Clear(result)
		if err != nil {
			return nil, err
		}
		result = next
	}
	return result, nil
}
