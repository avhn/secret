//go:build windows

package feature

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
	"golang.org/x/sys/windows"
)

func assertWindowsPrivate(t *testing.T, path string) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if secure.CheckPrivate(file) != nil {
		t.Fatal("native private object has wrong owner/DACL")
	}
}

func TestWindowsPrivateTemplate(t *testing.T) {
	home := t.TempDir()
	value := []byte("synthetic-private-payload")
	rendered, err := RenderTemplate(home, []byte("prefix={{TOKEN}}"), map[string][]byte{"TOKEN": value})
	if err != nil {
		t.Fatal(err)
	}
	defer rendered.Close()
	for _, path := range []string{filepath.Join(home, ".secrets"), filepath.Join(home, ".secrets", ".rendered"), filepath.Dir(rendered.Path()), rendered.Path()} {
		assertWindowsPrivate(t, path)
	}
	if err := rendered.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(rendered.Path())
	defer secure.Clear(data)
	if err != nil || !bytes.Equal(data, []byte("prefix=synthetic-private-payload")) || !bytes.Equal(value, []byte("synthetic-private-payload")) {
		t.Fatal("private render changed borrowed/published bytes")
	}
	path := rendered.Path()
	if err := rendered.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("private render cleanup failed")
	}
	// An inherited DACL is not repaired or accepted as private, even beneath a
	// private parent. A fresh namespace must be protected at object creation.
	bad := t.TempDir()
	if err := os.Mkdir(filepath.Join(bad, ".secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderTemplate(bad, []byte("{{TOKEN}}"), map[string][]byte{"TOKEN": value}); err != ErrTemplatePath {
		t.Fatal("permissive namespace accepted")
	}
}

func TestWindowsTemplateRejectsChangedACLAndCleanupIdentity(t *testing.T) {
	for _, target := range []string{"payload", "directory"} {
		t.Run(target, func(t *testing.T) {
			rendered, err := RenderTemplate(t.TempDir(), []byte("synthetic"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer rendered.Close()
			path := rendered.Path()
			if target == "directory" {
				path = filepath.Dir(path)
			}
			// Replace the binding, never grant access to a live secret-bearing file.
			if err := os.Rename(path, path+"-owned"); err != nil {
				t.Fatal(err)
			}
			if target == "payload" {
				err = os.WriteFile(path, []byte("synthetic-public"), 0600)
			} else {
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if rendered.Validate() != ErrTemplatePath {
				t.Fatal("rebound payload/directory accepted")
			}
			if rendered.Close() != ErrTemplateCleanup {
				t.Fatal("cleanup removed an unowned binding")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal("cleanup removed replacement")
			}
		})
	}
}

func TestWindowsPrivateAudit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := OpenAudit(AuditConfig{Enabled: true, Directory: dir, MaxBytes: 512, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	event := auditTestEvent()
	event.Target = "wincred:synthetic"
	for range 8 {
		if err := log.Record(event); err != nil {
			t.Fatal(err)
		}
	}
	result, err := log.Query(AuditQuery{})
	encoded, encodeErr := json.Marshal(event)
	// Retention is bounded by bytes, not a fixed count borrowed from a
	// differently sized provider reference. Include each JSONL newline.
	perFile := log.config.MaxBytes / (len(encoded) + 1)
	want := min(8, perFile*log.config.MaxFiles)
	if encodeErr != nil || err != nil || len(result.Events) != want {
		t.Fatalf("private audit rotation/query failed: %v, got %d events, want %d", err, len(result.Events), want)
	}
	assertWindowsPrivate(t, dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == ".audit-lock" || entry.IsDir() {
			t.Fatal("audit lock or scratch leaked")
		}
		assertWindowsPrivate(t, filepath.Join(dir, entry.Name()))
	}
	// A mode-only existing file is not safe even when its directory is private.
	if err := os.WriteFile(filepath.Join(dir, auditName(0)), []byte("synthetic-bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Query(AuditQuery{}); err != secure.ErrAudit {
		t.Fatal("invalid audit bytes accepted")
	}
	bad := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(bad, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAudit(AuditConfig{Enabled: true, Directory: bad}); err != secure.ErrAudit {
		t.Fatal("permissive audit directory accepted")
	}
}

func TestWindowsOperatorPrivateWorkflows(t *testing.T) {
	dir := testutil.TempDir(t)
	provider := &operatorProvider{}
	operator := Operator{SecretsDir: dir, Providers: map[string]backend.Provider{"wincred:synthetic": provider}}
	source := filepath.Join(dir, "source.env")
	if err := testutil.WriteFile(source, []byte("TOKEN=synthetic-import-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := ImportRequest{Source: "dotenv:" + source, Target: "wincred:synthetic"}
	operator.Confirm = func(OperatorResult) error { return secure.ErrConsent }
	if _, err := operator.Import(context.Background(), request); err != secure.ErrConsent || provider.gets+provider.puts+provider.deletes != 0 {
		t.Fatal("decline reached provider")
	}
	wantTarget, wantKey, wantNewKey := request.Target, "TOKEN", ""
	wantAction := store.ActionImport
	confirmations := 0
	operator.Confirm = func(result OperatorResult) error {
		confirmations++
		if result.Action != wantAction || result.Target != wantTarget || len(result.Records) != 1 || result.Records[0].Key != wantKey || result.Records[0].NewKey != wantNewKey {
			t.Fatal("consent omitted exact identity")
		}
		return nil
	}
	if _, err := operator.Import(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	path, _ := store.ManifestPath(dir, "wincred:synthetic")
	assertWindowsPrivate(t, path)
	wantAction = store.ActionRotate
	if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: "wincred:synthetic", Key: "TOKEN"}, func() ([]byte, error) { return []byte("synthetic-rotated"), nil }); err != nil {
		t.Fatal(err)
	}
	wantAction, wantNewKey = store.ActionRename, "RENAMED"
	if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRename, Reference: "wincred:synthetic", Key: "TOKEN", NewKey: "RENAMED"}, nil); err != nil {
		t.Fatal(err)
	}
	wantAction, wantKey, wantNewKey = store.ActionDelete, "RENAMED", ""
	if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionDelete, Reference: "wincred:synthetic", Key: "RENAMED"}, nil); err != nil {
		t.Fatal(err)
	}
	if len(provider.values) != 0 {
		t.Fatal("operator left obsolete accounts")
	}
	// The same hidden-input lifecycle goes through private file transactions.
	file := "file:" + source
	wantAction, wantTarget, wantKey = store.ActionRotate, file, "TOKEN"
	if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: file, Key: "TOKEN"}, func() ([]byte, error) { return []byte("synthetic-file-rotation"), nil }); err != nil {
		t.Fatal(err)
	}
	assertWindowsPrivate(t, source)
	if confirmations != 5 {
		t.Fatal("operator skipped exact consent")
	}
	for _, value := range provider.reads {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("operator retained provider bytes")
		}
	}
}

func TestWindowsDoctorRecoveryAndPrivateInput(t *testing.T) {
	dir := testutil.TempDir(t)
	path, _ := store.ManifestPath(dir, "wincred:synthetic")
	if err := store.WithManifestLock(path, "wincred", func(editor *store.ManifestEditor) error {
		return editor.PersistRecovery(store.RecoveryIntent{Version: store.MetadataVersion, Backend: "wincred", Prepared: []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}}})
	}); err != secure.ErrRecovery {
		t.Fatal("synthetic recovery was not retained")
	}
	report, err := RunDoctor(DoctorOptions{SecretsDir: dir, References: []string{"wincred:synthetic"}})
	if err != nil || len(report.Candidates) != 1 || report.Candidates[0].Account != operatorAccountA {
		t.Fatal("doctor did not inspect private names-only recovery")
	}
	bad := filepath.Join(dir, "public-input")
	if err := os.WriteFile(bad, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readOperatorFile(bad, false); err != secure.ErrTransaction {
		t.Fatal("operator accepted inherited file DACL")
	}
}

// Broaden only disposable synthetic objects, never a user's store. Preserve the
// object identity to prove validation rechecks DACLs rather than just FileInfo.
func broadenSyntheticDACL(t *testing.T, path string, directory bool) {
	t.Helper()
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint32(0)
	if directory {
		flags = windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(wide, windows.WRITE_DAC|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatal("cannot open disposable ACL fixture")
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil) != nil {
		t.Fatal("cannot change disposable ACL fixture")
	}
}

func TestWindowsTemplateRechecksDACL(t *testing.T) {
	for _, directory := range []bool{false, true} {
		rendered, err := RenderTemplate(t.TempDir(), []byte("synthetic"), nil)
		if err != nil {
			t.Fatal(err)
		}
		path := rendered.Path()
		if directory {
			path = filepath.Dir(path)
		}
		broadenSyntheticDACL(t, path, directory)
		if rendered.Validate() != ErrTemplatePath {
			t.Error("changed DACL accepted without rebinding")
		}
		if err := rendered.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWindowsAuditRechecksDACL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	log, err := OpenAudit(AuditConfig{Enabled: true, Directory: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Record(auditTestEvent()); err != nil {
		t.Fatal(err)
	}
	broadenSyntheticDACL(t, filepath.Join(dir, auditName(0)), false)
	if _, err := log.Query(AuditQuery{}); err != secure.ErrAudit {
		t.Fatal("audit accepted changed file DACL")
	}
}
