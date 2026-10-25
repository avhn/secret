package feature

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func passOperatorManifest(t *testing.T, dir, ref string, records []store.ManifestRecord) string {
	t.Helper()
	kind, _, _ := strings.Cut(ref, ":")
	path, err := store.ManifestPath(dir, ref)
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.EncodeManifest(records, kind)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestPassOperatorSharedNamesAndRecovery(t *testing.T) {
	for _, direction := range []struct{ source, target string }{{"libsecret:team", "pass:team"}, {"pass:team", "libsecret:team"}} {
		t.Run(direction.source, func(t *testing.T) {
			operator := newTestOperator(t)
			source := &operatorProvider{values: map[string][]byte{operatorAccountA: []byte("synthetic-pass-value")}}
			target := &operatorProvider{}
			operator.Providers[direction.source] = source
			operator.Providers[direction.target] = target
			passOperatorManifest(t, operator.SecretsDir, direction.source, []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
			request := ExportRequest{Source: direction.source, Target: direction.target, OnConflict: "fail"}
			if _, err := operator.PreflightExport(request); err != nil {
				t.Fatal("isolated same-name manifests collided")
			}
			if source.gets+target.gets+target.puts != 0 {
				t.Fatal("preflight fetched values")
			}
			if _, err := operator.Export(context.Background(), request); err != nil {
				t.Fatal(err)
			}
			if source.gets != 1 || target.puts != 1 {
				t.Fatal("export did not use providers")
			}
			if _, err := operator.PreflightExport(request); err != secure.ErrConflict {
				t.Fatal("identity collision ignored")
			}
			path, _ := store.ManifestPath(operator.SecretsDir, direction.target)
			kind, _, _ := strings.Cut(direction.target, ":")
			intent := store.RecoveryIntent{Version: 1, Backend: kind, Prepared: []store.ManifestRecord{{Key: "OTHER", Account: operatorAccountB}}}
			data, _ := json.Marshal(intent)
			if err := os.WriteFile(path+".recovery", data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := operator.PreflightLifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: direction.target, Key: "TOKEN"}); err != secure.ErrRecovery {
				t.Fatal("wrong recovery lookup")
			}
		})
	}
	operator := newTestOperator(t)
	if _, err := operator.PreflightExport(ExportRequest{Source: "libsecret:team", Target: "keychain:team", OnConflict: "fail"}); err != secure.ErrConflict {
		t.Fatal("legacy shared manifest collision accepted")
	}
}
func TestPassMetadataWithoutProvider(t *testing.T) {
	operator := newTestOperator(t)
	ref := "pass:team"
	path := passOperatorManifest(t, operator.SecretsDir, ref, []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
	provider := &operatorProvider{failGet: true}
	operator.Providers[ref] = provider
	t.Setenv("PATH", t.TempDir())
	t.Setenv("PASSWORD_STORE_DIR", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("PASSWORD_STORE_SIGNING_KEY", "invalid")
	metadata, err := ReadMetadata(ref, operator.SecretsDir)
	if err != nil || metadata.Backend != "pass" || len(metadata.Records) != 1 {
		t.Fatal("pass metadata required a provider")
	}
	if !explicitMetadataReference(ref) || !validOperatorReference(ref) {
		t.Fatal("pass reference not accepted")
	}
	if _, err := DiffMetadata(metadata, metadata, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Complete(CompletionRequest{}, []store.Metadata{metadata}); err != nil {
		t.Fatal(err)
	}
	server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{ref}, Directory: operator.SecretsDir})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "show", map[string]any{"reference": ref})); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.ListNames(operator.SecretsDir, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.metadata(ref, false); err != nil {
		t.Fatal(err)
	}
	report, err := runDoctor(DoctorOptions{SecretsDir: operator.SecretsDir, References: []string{ref}}, func(string) (string, error) { return "", os.ErrNotExist })
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, check := range report.Checks {
		if check.Kind == "alias" && check.Target == path {
			found = true
		}
	}
	if !found || provider.gets+provider.puts+provider.deletes != 0 {
		t.Fatal("metadata used provider or wrong manifest")
	}
}
func TestPassImportAndLifecycle(t *testing.T) {
	operator := newTestOperator(t)
	ref := "pass:team"
	provider := &operatorProvider{}
	operator.Providers[ref] = provider
	source := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(source, []byte("TOKEN=synthetic-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := ImportRequest{Source: "dotenv:" + source, Target: ref}
	operator.Confirm = func(OperatorResult) error { return secure.ErrConsent }
	if _, err := operator.Import(context.Background(), request); err != secure.ErrConsent || provider.puts != 0 {
		t.Fatal("consent boundary failed")
	}
	operator.Confirm = func(OperatorResult) error { return nil }
	if _, err := operator.Import(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for _, action := range []store.OperatorAction{store.ActionRotate, store.ActionRename, store.ActionDelete} {
		request := LifecycleRequest{Action: action, Reference: ref, Key: "TOKEN"}
		var input func() ([]byte, error)
		if action == store.ActionRotate {
			input = func() ([]byte, error) { return []byte("synthetic-rotated"), nil }
		}
		if action == store.ActionRename {
			request.NewKey = "RENAMED"
		}
		if action == store.ActionDelete {
			request.Key = "RENAMED"
		}
		if _, err := operator.Lifecycle(request, input); err != nil {
			t.Fatal(err)
		}
	}
	records, err := backend.ListNames(operator.SecretsDir, ref)
	if err != nil || len(records) != 0 {
		t.Fatal("lifecycle inventory differs")
	}
}
