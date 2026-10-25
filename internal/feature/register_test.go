package feature

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func syntheticRegistration() RegisterRequest {
	return RegisterRequest{Target: "onepassword:test", Key: "TOKEN", Labels: map[string]string{"env": "dev"}, Provider: store.OnePasswordReference{Reference: "op://" + strings.Repeat("v", 26) + "/" + strings.Repeat("i", 26) + "/password", AccountUUID: strings.Repeat("a", 26), Auth: "service-account"}}
}

type registrationAudit struct{ events []store.AuditEvent }

func (a *registrationAudit) Record(event store.AuditEvent) error {
	a.events = append(a.events, event)
	return nil
}
func TestOnePasswordRegistrationConsentAndAudit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private Unix writer")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "not-created")
	audit := &registrationAudit{}
	registrar := Registrar{SecretsDir: directory, Audit: audit, Confirm: func(RegisterRequest) error { return secure.ErrConsent }}
	if err := registrar.register(syntheticRegistration()); err != secure.ErrConsent {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) || len(audit.events) != 0 {
		t.Fatal("decline touched destination or audit")
	}
	calls := 0
	registrar.Confirm = func(request RegisterRequest) error {
		calls++
		if _, err := os.Stat(directory); !os.IsNotExist(err) {
			t.Fatal("directory accessed before consent")
		}
		return nil
	}
	if err := registrar.register(syntheticRegistration()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(audit.events) != 1 || !validAuditEvent(audit.events[0]) {
		t.Fatal("missing names-only register audit")
	}
	data, _ := json.Marshal(audit.events)
	request := syntheticRegistration()
	if bytes.Contains(data, []byte(request.Provider.Reference)) || bytes.Contains(data, []byte(request.Provider.AccountUUID)) {
		t.Fatal("provider coordinates in audit")
	}
	registrar.Confirm = func(RegisterRequest) error { return nil }
	original, _ := os.ReadFile(filepath.Join(directory, "test.onepassword-keys"))
	changed := request
	changed.Provider.Reference = strings.TrimSuffix(request.Provider.Reference, "password") + "other"
	if err := registrar.register(changed); err != secure.ErrConflict {
		t.Fatalf("retarget: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(directory, "test.onepassword-keys"))
	if !bytes.Equal(original, after) {
		t.Fatal("retarget changed inventory")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatal("lock or recovery debris")
	}
}
func TestOnePasswordReadOnlyFeaturePreflight(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "absent")
	provider := &operatorProvider{}
	confirms, reads := 0, 0
	operator := Operator{SecretsDir: directory, Providers: map[string]backend.Provider{"onepassword:test": provider}, Confirm: func(OperatorResult) error { confirms++; return nil }, runImport: func(context.Context, string, []string) ([]byte, error) {
		reads++
		return nil, errors.New("synthetic-provider-stderr-sentinel")
	}}
	source := "dotenv:" + filepath.Join(root, "does-not-exist")
	request := ImportRequest{Source: source, Target: "onepassword:test"}
	for _, dryRun := range []bool{false, true} {
		request.DryRun = dryRun
		if _, err := operator.PreflightImport(request); err != backend.ErrReadOnly {
			t.Fatal(err)
		}
		if _, err := operator.Import(context.Background(), request); err != backend.ErrReadOnly {
			t.Fatal(err)
		}
	}
	if _, _, err := validateImportRequest(request); err != backend.ErrReadOnly {
		t.Fatal("request validation read-only error lost")
	}
	for _, request := range []ExportRequest{{Source: "onepassword:test", Target: "libsecret:target", OnConflict: "fail"}, {Source: "file:" + filepath.Join(root, "absent-source"), Target: "onepassword:test", OnConflict: "fail"}} {
		if _, err := operator.Export(context.Background(), request); err != backend.ErrReadOnly {
			t.Fatal(err)
		}
	}
	for _, action := range []store.OperatorAction{store.ActionRotate, store.ActionRename, store.ActionDelete} {
		if _, err := operator.Lifecycle(LifecycleRequest{Action: action, Reference: "onepassword:test", Key: "TOKEN", NewKey: "NEW"}, func() ([]byte, error) { reads++; return []byte("synthetic"), nil }); err != backend.ErrReadOnly {
			t.Fatal(err)
		}
	}
	if operatorError(backend.ErrReadOnly) != backend.ErrReadOnly {
		t.Fatal("translated read-only error")
	}
	if confirms != 0 || reads != 0 || provider.gets+provider.puts+provider.deletes != 0 {
		t.Fatal("read-only preflight reached side effects")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("read-only preflight created directory")
	}
	if validOperatorReference("onepassword:test") {
		t.Fatal("metadata support widened writable references")
	}
}
func TestOnePasswordMetadataProjection(t *testing.T) {
	dir := testutil.TempDir(t)
	request := syntheticRegistration()
	record := store.ManifestV2Record{Key: request.Key, Labels: request.Labels, ID: strings.Repeat("c", 32), Provider: request.Provider}
	data, err := store.EncodeManifestV2([]store.ManifestV2Record{record}, "onepassword")
	if err != nil {
		t.Fatal(err)
	}
	if err := testutil.WriteFile(filepath.Join(dir, "test.onepassword-keys"), data, 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := readOnePasswordMetadata("onepassword:test", dir)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := BuildInventory([]store.Metadata{metadata}, nil)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := DiffMetadata(metadata, metadata, nil, store.Selectors{"env": "dev"})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := Complete(CompletionRequest{Command: "run", Flag: "reference"}, []store.Metadata{metadata})
	if err != nil || len(completion) != 1 {
		t.Fatal(err)
	}
	for _, value := range []any{metadata, inventory, diff, completion} {
		out, _ := json.Marshal(value)
		if bytes.Contains(out, []byte(request.Provider.Reference)) || bytes.Contains(out, []byte(request.Provider.AccountUUID)) {
			t.Fatal("provider coordinates exposed")
		}
	}
	if metadata.Records[0].Account != record.ID {
		t.Fatal("account meaning changed")
	}
	event := store.AuditEvent{Version: 1, Time: time.Now(), Action: store.ActionRegister, Target: request.Target, Keys: []string{request.Key}, Labels: request.Labels, Outcome: store.AuditSuccess}
	if !event.Action.Valid() || !validAuditEvent(event) {
		t.Fatal("register rejected by audit")
	}
	event.Target = "libsecret:test"
	if validAuditEvent(event) {
		t.Fatal("writable target accepted registration action")
	}
	if _, err := ReadMetadata("onepassword:test", filepath.Join(dir, "absent")); err != secure.ErrUnsupported {
		t.Fatal("default metadata dispatch enabled")
	}
	server, err := NewMCPServer(MCPConfig{Enabled: true, Directory: dir, Stores: []string{"onepassword:test"}})
	if err != nil {
		t.Fatal(err)
	}
	server.read = func(reference, directory string) (store.Metadata, error) {
		return readOnePasswordMetadata(reference, directory)
	}
	if _, err := server.inventory([]string{"onepassword:test"}, nil); err != nil {
		t.Fatal(err)
	}
}
func TestOnePasswordDefaultRegistrationDisabled(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent")
	calls := 0
	registrar := Registrar{SecretsDir: directory, Confirm: func(RegisterRequest) error { calls++; return nil }}
	if err := registrar.Register(syntheticRegistration()); err != backend.ErrUnsupported || calls != 0 {
		t.Fatal("default registration enabled")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("default registration touched destination")
	}
}
func TestOnePasswordDoctorPresenceOnly(t *testing.T) {
	calls := 0
	report, err := runDoctor(DoctorOptions{References: []string{"onepassword:test"}}, func(tool string) (string, error) {
		if tool == "op" {
			calls++
		}
		return "/synthetic/" + tool, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("doctor: %v calls=%d", err, calls)
	}
	found := false
	for _, check := range report.Checks {
		if check.Target == "onepassword" && check.Status == "present" {
			found = true
		}
	}
	if !found {
		t.Fatal("missing presence-only report")
	}
}
