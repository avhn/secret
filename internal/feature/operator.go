package feature

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const (
	// MaxOperatorBytes bounds new operator file and importer inputs, not legacy reads.
	MaxOperatorBytes      = 16 << 20
	MaxOperatorValueBytes = 64 << 10
	maxOperatorRecords    = 1024
)

// Operator performs synchronous operations after the CLI's terminal and exact
// consent boundary. Preflight methods are names-only but still require the CLI
// to gate stdin and stdout before access. There is no consent bypass or JSON
// operator mode. Providers permits explicit isolated test injection; nil uses
// normal dispatch. Never format this object or a value-bearing mutation.
type Operator struct {
	SecretsDir string
	Providers  map[string]backend.Provider
	// Confirm must bridge to the already-open real OperatorTerminal.Confirm.
	// It receives the exact planned identities before any value fetch or write.
	// Nil rejects execution; it is not a consent flag or an agent-facing bypass.
	Confirm   func(OperatorResult) error
	runImport func(context.Context, string, []string) ([]byte, error)
}

// OperatorRecord describes an exact identity and a destination collision only.
type OperatorRecord struct {
	Key      string            `json:"key"`
	NewKey   string            `json:"new_key,omitempty"`
	Labels   map[string]string `json:"labels"`
	Conflict bool              `json:"conflict"`
}

// OperatorResult is names-only dry-run/status data, not an operator JSON mode.
// A dry run never claims provider field existence or transaction success.
type OperatorResult struct {
	Action  store.OperatorAction `json:"action"`
	Source  string               `json:"source,omitempty"`
	Target  string               `json:"target"`
	Records []OperatorRecord     `json:"records"`
}

// ExportRequest requires explicit references and the literal conflict policy
// "fail". Empty Selectors selects unlabeled records only, not every section.
type ExportRequest struct {
	Source, Target string
	Selectors      store.Selectors
	Keys           []string
	OnConflict     string
	DryRun         bool
}

// LifecycleRequest addresses exact labels, not subset selection. Rotate gets its
// value only from the confirmed CLI terminal's ReadValue callback.
type LifecycleRequest struct {
	Action                 store.OperatorAction
	Reference, Key, NewKey string
	Labels                 map[string]string
}

func validOperatorText(text string) bool {
	if text == "" || len(text) > 4096 || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

func validOperatorReference(reference string) bool {
	if !validOperatorText(reference) {
		return false
	}
	if strings.HasPrefix(reference, "file:") {
		path := strings.TrimPrefix(reference, "file:")
		return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != string(filepath.Separator)
	}
	if !store.ProviderReference(reference) {
		return false
	}
	_, err := (store.Locator{}).Resolve(reference)
	return err == nil
}

func (operator Operator) validate() error {
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(operator.SecretsDir) || !validOperatorText(operator.SecretsDir) {
		return secure.ErrInvalidRequest
	}
	if store.ValidateDirectory(operator.SecretsDir) != nil {
		return secure.ErrInvalidRequest
	}
	return nil
}

// readOperatorFile uses an anchored parent and validates the final identity,
// rejecting final aliases and nonregular inputs before a bounded read. Missing targets
// are allowed only for destination preflight. No input bytes enter an error.
func readOperatorFile(path string, missing bool) ([]byte, error) {
	root, err := openOperatorParent(path)
	if err != nil {
		if missing && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, secure.ErrTransaction
	}
	defer root.Close()
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if missing && os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > MaxOperatorBytes {
		return nil, secure.ErrTransaction
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, secure.ErrTransaction
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, secure.ErrTransaction
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxOperatorBytes+1))
	if err != nil || len(data) > MaxOperatorBytes {
		secure.Clear(data)
		return nil, secure.ErrTransaction
	}
	return data, nil
}

func openOperatorParent(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, secure.ErrInvalidRequest
	}
	// Normal platform aliases such as macOS /var and /tmp are valid explicit
	// input paths. Bind their resolved parent once; never follow a final alias.
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(parent)
}

func (operator Operator) metadata(reference string, missing bool) (store.Metadata, error) {
	result := store.Metadata{Version: store.MetadataVersion, Reference: reference, Backend: "file"}
	if strings.HasPrefix(reference, "file:") {
		data, err := readOperatorFile(strings.TrimPrefix(reference, "file:"), missing)
		defer secure.Clear(data)
		if err != nil {
			return store.Metadata{}, err
		}
		result.Records, _ = store.ParseMetadata(data)
		return result, nil
	}
	kind, _, _ := strings.Cut(reference, ":")
	path, err := store.ManifestPath(operator.SecretsDir, reference)
	if err != nil {
		return store.Metadata{}, secure.ErrInvalidRequest
	}
	data, err := readOperatorFile(path, missing)
	defer secure.Clear(data)
	if err != nil {
		return store.Metadata{}, err
	}
	result.Backend = kind
	if data == nil && missing {
		return result, nil
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return store.Metadata{}, secure.ErrTransaction
	}
	records, err := store.ParseManifest(data, kind)
	if err != nil {
		return store.Metadata{}, secure.ErrTransaction
	}
	for _, record := range records {
		result.Records = append(result.Records, store.MetadataRecord{Key: record.Key, Labels: record.Labels, Account: record.Account})
	}
	return result, nil
}

func (operator Operator) provider(reference string) (backend.Provider, string, error) {
	provider, _, service, err := backend.DispatchWith(reference, operator.Providers[reference])
	if err != nil {
		return nil, "", secure.ErrInvalidRequest
	}
	return provider, service, nil
}

func (operator Operator) transaction(reference string, insertOnly, replaceOnly bool) store.Transaction {
	if strings.HasPrefix(reference, "file:") {
		return store.FileTransaction{SecretsDir: operator.SecretsDir, Path: strings.TrimPrefix(reference, "file:"), FailOnConflict: insertOnly, RequireExisting: replaceOnly}
	}
	return backend.Transaction{SecretsDir: operator.SecretsDir, Reference: reference, Provider: operator.Providers[reference], FailOnConflict: insertOnly, RequireExisting: replaceOnly}
}

func operatorResult(action store.OperatorAction, source, target string, mutations []store.Mutation, existing []store.MetadataRecord) OperatorResult {
	result := OperatorResult{Action: action, Source: source, Target: target, Records: make([]OperatorRecord, 0, len(mutations))}
	identities := make(map[string]bool)
	for _, record := range existing {
		identities[record.Key+"\x00"+store.CanonicalLabels(record.Labels)] = true
	}
	for _, mutation := range mutations {
		result.Records = append(result.Records, OperatorRecord{Key: mutation.Key, NewKey: mutation.NewKey, Labels: copyMetadataLabels(mutation.Labels), Conflict: identities[mutation.Key+"\x00"+store.CanonicalLabels(mutation.Labels)]})
	}
	return result
}

func clearOperatorMutations(mutations []store.Mutation) {
	for i := range mutations {
		secure.Clear(mutations[i].Value)
		mutations[i].Value = nil
	}
}

func (operator Operator) confirm(result OperatorResult) error {
	if operator.Confirm == nil {
		return secure.ErrConsent
	}
	if err := operator.Confirm(result); err != nil {
		return secure.ErrConsent
	}
	return nil
}

func operatorError(err error) error {
	switch err {
	case nil, backend.ErrReadOnly, secure.ErrInvalidRequest, secure.ErrUnsupported, secure.ErrConflict, secure.ErrNotFound, secure.ErrRecovery, secure.ErrConsent, secure.ErrInput:
		return err
	default:
		return secure.ErrTransaction
	}
}

func (operator Operator) exportPlan(request ExportRequest) (OperatorResult, []store.Mutation, []store.MetadataRecord, error) {
	for _, ref := range []string{request.Source, request.Target} {
		if err := backend.ReadOnlyReference(ref); err != nil {
			return OperatorResult{}, nil, nil, err
		}
	}
	if err := operator.validate(); err != nil {
		return OperatorResult{}, nil, nil, err
	}
	if !validOperatorReference(request.Source) || !validOperatorReference(request.Target) || strings.HasPrefix(request.Target, "file:") || request.Source == request.Target || request.OnConflict != "fail" || store.ValidateIdentity("KEY", request.Selectors) != nil || len(request.Keys) > maxOperatorRecords {
		return OperatorResult{}, nil, nil, secure.ErrInvalidRequest
	}
	// Compare storage identities, not names: optional suffixes isolate manifests.
	if !strings.HasPrefix(request.Source, "file:") {
		sourcePath, sourceErr := store.ManifestPath(operator.SecretsDir, request.Source)
		targetPath, targetErr := store.ManifestPath(operator.SecretsDir, request.Target)
		if sourceErr != nil || targetErr != nil {
			return OperatorResult{}, nil, nil, secure.ErrInvalidRequest
		}
		if sourcePath == targetPath {
			return OperatorResult{}, nil, nil, secure.ErrConflict
		}
	}
	seen := make(map[string]bool)
	for _, key := range request.Keys {
		if store.ValidateIdentity(key, nil) != nil || seen[key] {
			return OperatorResult{}, nil, nil, secure.ErrInvalidRequest
		}
		seen[key] = true
	}
	source, err := operator.metadata(request.Source, false)
	if err != nil {
		return OperatorResult{}, nil, nil, err
	}
	selection, err := SelectMetadata(source, request.Selectors)
	if err != nil {
		return OperatorResult{}, nil, nil, secure.ErrInvalidRequest
	}
	keys := request.Keys
	if len(keys) == 0 {
		for _, key := range selection.Keys {
			if _, ok := selection.Matched[key]; ok {
				keys = append(keys, key)
			}
		}
	}
	if len(keys) == 0 || len(keys) > maxOperatorRecords {
		return OperatorResult{}, nil, nil, secure.ErrNotFound
	}
	mutations := make([]store.Mutation, 0, len(keys))
	records := make([]store.MetadataRecord, 0, len(keys))
	for _, key := range keys {
		record, ok := selection.Matched[key]
		if !ok {
			return OperatorResult{}, nil, nil, secure.ErrNotFound
		}
		records = append(records, record)
		mutations = append(mutations, store.Mutation{Kind: store.MutationPut, Key: key, Labels: record.Labels})
	}
	destination, err := operator.destinationMetadata(request.Target)
	if err != nil {
		return OperatorResult{}, nil, nil, err
	}
	result := operatorResult(store.ActionExport, request.Source, request.Target, mutations, destination.Records)
	if err := store.CheckMutationConflicts(destination.Records, mutations, true, false); err != nil {
		return result, nil, nil, err
	}
	return result, mutations, records, nil
}

// PreflightExport validates all references, selections and destination identities
// without any provider Get/Put/Delete. Conflicting names are returned with ErrConflict.
func (operator Operator) PreflightExport(request ExportRequest) (OperatorResult, error) {
	result, _, _, err := operator.exportPlan(request)
	return result, err
}

// Export plans names-only identities, requires Confirm, loads selected bytes,
// and publishes through the insert-only transaction, which rechecks under lock.
// The CLI must establish real terminals before calling this method.
func (operator Operator) Export(ctx context.Context, request ExportRequest) (OperatorResult, error) {
	result, mutations, records, err := operator.exportPlan(request)
	if err != nil || request.DryRun {
		return result, err
	}
	defer clearOperatorMutations(mutations)
	if ctx == nil || ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	if err := operator.confirm(result); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	if strings.HasPrefix(request.Source, "file:") {
		data, err := readOperatorFile(strings.TrimPrefix(request.Source, "file:"), false)
		defer secure.Clear(data)
		if err != nil {
			return result, err
		}
		metadata, _ := store.ParseMetadata(data)
		snapshot := store.Metadata{Version: store.MetadataVersion, Reference: request.Source, Backend: "file", Records: metadata}
		selection, err := SelectMetadata(snapshot, request.Selectors)
		if err != nil {
			return result, secure.ErrConflict
		}
		for _, wanted := range records {
			selected, ok := selection.Matched[wanted.Key]
			if !ok || selected.Line != wanted.Line || store.CanonicalLabels(selected.Labels) != store.CanonicalLabels(wanted.Labels) {
				return result, secure.ErrConflict
			}
		}
		parsed, _ := store.Parse(data)
		defer func() {
			for _, record := range parsed {
				secure.Clear(record.Value)
			}
		}()
		for i, wanted := range records {
			// A file may have changed since preflight. Refuse identity/line drift
			// rather than move a differently selected value under prior consent.
			found := false
			for _, record := range parsed {
				if record.Line == wanted.Line && record.Key == wanted.Key && store.CanonicalLabels(record.Labels) == store.CanonicalLabels(wanted.Labels) {
					mutations[i].Value = secure.Clone(record.Value)
					found = true
					break
				}
			}
			if !found {
				return result, secure.ErrConflict
			}
		}
	} else {
		provider, service, err := operator.provider(request.Source)
		if err != nil {
			return result, err
		}
		for i, record := range records {
			if ctx.Err() != nil {
				return result, secure.ErrTransaction
			}
			value, err := provider.Get(service, record.Account)
			if err != nil {
				secure.Clear(value)
				return result, secure.ErrTransaction
			}
			mutations[i].Value = value
		}
	}
	for _, mutation := range mutations {
		if len(mutation.Value) > MaxOperatorValueBytes {
			return result, secure.ErrInvalidRequest
		}
	}
	if ctx.Err() != nil {
		return result, secure.ErrTransaction
	}
	return result, operatorError(operator.transaction(request.Target, true, false).Apply(mutations))
}

func (operator Operator) lifecyclePlan(request LifecycleRequest) (OperatorResult, []store.Mutation, error) {
	if err := backend.ReadOnlyReference(request.Reference); err != nil {
		return OperatorResult{}, nil, err
	}
	if err := operator.validate(); err != nil {
		return OperatorResult{}, nil, err
	}
	if !validOperatorReference(request.Reference) || store.ValidateIdentity(request.Key, request.Labels) != nil {
		return OperatorResult{}, nil, secure.ErrInvalidRequest
	}
	mutation := store.Mutation{Key: request.Key, Labels: copyMetadataLabels(request.Labels)}
	switch request.Action {
	case store.ActionRotate:
		mutation.Kind = store.MutationPut
	case store.ActionDelete:
		mutation.Kind = store.MutationDelete
	case store.ActionRename:
		mutation.Kind, mutation.NewKey = store.MutationRename, request.NewKey
	default:
		return OperatorResult{}, nil, secure.ErrInvalidRequest
	}
	if request.Action != store.ActionRename && request.NewKey != "" {
		return OperatorResult{}, nil, secure.ErrInvalidRequest
	}
	metadata, err := operator.destinationMetadata(request.Reference)
	if err != nil {
		return OperatorResult{}, nil, err
	}
	mutations := []store.Mutation{mutation}
	if err := store.CheckMutationConflicts(metadata.Records, mutations, false, request.Action == store.ActionRotate); err != nil {
		return OperatorResult{}, nil, err
	}
	return operatorResult(request.Action, "", request.Reference, mutations, nil), mutations, nil
}

// PreflightLifecycle checks exact identities without a value-provider call.
func (operator Operator) PreflightLifecycle(request LifecycleRequest) (OperatorResult, error) {
	result, _, err := operator.lifecyclePlan(request)
	return result, err
}

// Lifecycle runs after exact CLI consent. readValue must be the confirmed real
// terminal's hidden ReadValue method, never argv, stdin or a bypass callback in
// production. It is invoked only for rotation and only after names-only preflight.
// Returned input ownership transfers here and is cleared on every path.
func (operator Operator) Lifecycle(request LifecycleRequest, readValue func() ([]byte, error)) (OperatorResult, error) {
	result, mutations, err := operator.lifecyclePlan(request)
	if err != nil {
		return result, err
	}
	defer clearOperatorMutations(mutations)
	if err := operator.confirm(result); err != nil {
		return result, err
	}
	if request.Action == store.ActionRotate {
		if readValue == nil {
			return result, secure.ErrInput
		}
		value, err := readValue()
		mutations[0].Value = value
		if err != nil {
			return result, secure.ErrInput
		}
		if len(value) > MaxOperatorValueBytes {
			return result, secure.ErrInvalidRequest
		}
	} else if readValue != nil {
		return result, secure.ErrInvalidRequest
	}
	return result, operatorError(operator.transaction(request.Reference, false, request.Action == store.ActionRotate).Apply(mutations))
}
