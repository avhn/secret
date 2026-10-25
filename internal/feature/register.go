package feature

import (
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// RegisterRequest contains only validated names and immutable provider coordinates.
// It is intentionally separate from writable operator requests and value import.
type RegisterRequest struct {
	Target   string
	Key      string
	Labels   map[string]string
	Provider store.OnePasswordReference
}

func ValidateRegisterRequest(request RegisterRequest) error {
	kind, name, ok := strings.Cut(request.Target, ":")
	if !ok || kind != "onepassword" || name == "" || len(request.Key) > 256 || len(request.Labels) > 128 || store.ValidateIdentity(request.Key, request.Labels) != nil || store.ValidateOnePasswordReference(request.Provider) != nil {
		return secure.ErrInvalidRequest
	}
	if _, err := (store.Locator{}).Resolve(request.Target); err != nil {
		return secure.ErrInvalidRequest
	}
	return nil
}

// Registrar never calls a provider. Confirmation must display the entire
// validated registration request, before even examining the destination directory.
type Registrar struct {
	SecretsDir string
	Confirm    func(RegisterRequest) error
	Audit      store.AuditSink
}

func (registrar Registrar) Register(request RegisterRequest) error {
	if !backend.OnePasswordEnabled() {
		return backend.ErrUnsupported
	}
	return registrar.register(request)
}
func (registrar Registrar) register(request RegisterRequest) error {
	if err := ValidateRegisterRequest(request); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return secure.ErrUnsupported
	}
	if !filepath.IsAbs(registrar.SecretsDir) || !validOperatorText(registrar.SecretsDir) {
		return secure.ErrInvalidRequest
	}
	if registrar.Confirm == nil {
		return secure.ErrConsent
	}
	if err := registrar.Confirm(request); err != nil {
		return err
	}
	// No stat, lock, audit creation or random ID generation precedes confirmation.
	id, err := store.NewAccount()
	if err != nil {
		return secure.ErrTransaction
	}
	labels := copyMetadataLabels(request.Labels)
	_, name, _ := strings.Cut(request.Target, ":")
	err = store.RegisterManifestV2(filepath.Join(registrar.SecretsDir, name+".onepassword-keys"), store.ManifestV2Record{Key: request.Key, Labels: labels, ID: id, Provider: request.Provider})
	if err != nil {
		return err
	}
	if registrar.Audit != nil {
		if registrar.Audit.Record(store.AuditEvent{Version: store.MetadataVersion, Time: time.Now().UTC(), Action: store.ActionRegister, Target: request.Target, Keys: []string{request.Key}, Labels: labels, Outcome: store.AuditSuccess}) != nil {
			return secure.ErrAudit
		}
	}
	return nil
}

func readOnePasswordMetadata(reference, directory string) (store.Metadata, error) {
	if _, err := (store.Locator{}).Resolve(reference); err != nil || directory == "" {
		return store.Metadata{}, ErrMetadata
	}
	_, name, _ := strings.Cut(reference, ":")
	records, err := store.ReadManifestV2(filepath.Join(directory, name+".onepassword-keys"), "onepassword")
	if err != nil {
		return store.Metadata{}, ErrMetadataRead
	}
	result := store.Metadata{Version: store.MetadataVersion, Reference: reference, Backend: "onepassword", Records: make([]store.MetadataRecord, 0, len(records))}
	for _, r := range store.ProjectManifestV2(records) {
		result.Records = append(result.Records, store.MetadataRecord{Key: r.Key, Labels: r.Labels, Account: r.Account})
	}
	return result, nil
}
