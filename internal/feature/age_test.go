package feature

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func featureAgeFixture(t *testing.T) (Operator, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix age filesystem")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".secrets")
	keys := filepath.Join(dir, ".age-keys")
	if err := os.MkdirAll(keys, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("generate")
	}
	identity := filepath.Join(keys, "identity")
	recipients := filepath.Join(keys, "recipients")
	data := []byte(id.String() + "\n")
	defer secure.Clear(data)
	if os.WriteFile(identity, data, 0600) != nil || os.WriteFile(recipients, []byte(id.Recipient().String()+"\n"), 0600) != nil {
		t.Fatal("write fixture")
	}
	config := backend.AgeConfig{Home: home, SecretsDir: dir, IdentityFile: identity}
	for _, ref := range []string{"age:source", "age:target"} {
		if err := config.Init(ref, recipients); err != nil {
			t.Fatal(err)
		}
	}
	if err := (backend.AgeTransaction{Config: config, Reference: "age:source"}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("SYNTHETIC-AGE-FEATURE")}, {Kind: store.MutationPut, Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Value: []byte("SYNTHETIC-AGE-PROD")}}); err != nil {
		t.Fatal(err)
	}
	operator := Operator{SecretsDir: dir, Age: config, Confirm: func(OperatorResult) error { return nil }}
	return operator, recipients
}
func TestAgeNamesOnlyInterfaces(t *testing.T) {
	operator, _ := featureAgeFixture(t)
	// Remove the identity: every names-only surface must continue to work.
	if os.Remove(operator.Age.IdentityFile) != nil {
		t.Fatal("remove identity")
	}
	metadata, err := ReadMetadata("age:source", operator.SecretsDir)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := BuildInventory([]store.Metadata{metadata}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(inventory)
	if bytes.Contains(data, []byte("SYNTHETIC-AGE")) || bytes.Contains(data, []byte("recipient")) || bytes.Contains(data, []byte("ciphertext")) {
		t.Fatal("metadata leak")
	}
	if _, err := DiffMetadata(metadata, metadata, nil, store.Selectors{"env": "prod"}); err != nil {
		t.Fatal(err)
	}
	candidates, err := Complete(CompletionRequest{Command: "run", Flag: "--key"}, []store.Metadata{metadata})
	if err != nil || len(candidates) != 1 || candidates[0] != "TOKEN" {
		t.Fatal("completion")
	}
	server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{"age:source"}, Directory: operator.SecretsDir})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	input := strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"show\",\"arguments\":{\"reference\":\"age:source\"}}}\n")
	if err := server.Serve(input, &output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("SYNTHETIC-AGE")) {
		t.Fatal("MCP leak")
	}
}
func TestAgeOperatorExportAndImport(t *testing.T) {
	operator, _ := featureAgeFixture(t)
	result, err := operator.Export(context.Background(), ExportRequest{Source: "age:source", Target: "age:target", Selectors: store.Selectors{"env": "prod"}, OnConflict: "fail"})
	if err != nil || len(result.Records) != 1 {
		t.Fatal(err)
	}
	snapshot, err := operator.Age.Read("age:target")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Records) != 1 || !bytes.Equal(snapshot.Records[0].Value, []byte("SYNTHETIC-AGE-PROD")) {
		t.Fatal("wrong source selection")
	}
	snapshot.Close()
	path := filepath.Join(operator.Age.Home, "import.env")
	if os.WriteFile(path, []byte("IMPORTED=synthetic-import\n"), 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := operator.Import(context.Background(), ImportRequest{Source: "dotenv:" + path, Target: "age:target"}); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Import(context.Background(), ImportRequest{Source: "dotenv:" + path, Target: "age:target"}); err != secure.ErrConflict {
		t.Fatal("insert-only conflict")
	}
	for _, request := range []LifecycleRequest{{Action: store.ActionRename, Reference: "age:target", Key: "IMPORTED", NewKey: "RENAMED"}, {Action: store.ActionDelete, Reference: "age:target", Key: "RENAMED"}} {
		if _, err := operator.Lifecycle(request, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: "age:target", Key: "TOKEN", Labels: map[string]string{"env": "prod"}}, func() ([]byte, error) { return []byte("rotated-synthetic"), nil }); err != nil {
		t.Fatal(err)
	}
}
func TestAgePlaintextRoutesRejectedBeforeValues(t *testing.T) {
	operator, _ := featureAgeFixture(t)
	target := "file:" + filepath.Join(operator.Age.Home, "must-not-exist")
	os.Remove(operator.Age.IdentityFile)
	for _, request := range []ImportRequest{{Source: "age:source", Target: target}, {Source: "age:source", Target: "age:target"}} {
		if _, err := operator.Import(context.Background(), request); err != secure.ErrInvalidRequest {
			t.Fatal("age import source accepted")
		}
	}
	if _, err := operator.Export(context.Background(), ExportRequest{Source: "age:source", Target: target, OnConflict: "fail"}); err != secure.ErrInvalidRequest {
		t.Fatal("plaintext route reached values")
	}
	if _, err := os.Stat(strings.TrimPrefix(target, "file:")); !os.IsNotExist(err) {
		t.Fatal("plaintext target created")
	}
}
func TestAgeConcurrentSourceSelectionDrift(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "implicit", true: "explicit"}[explicit], func(t *testing.T) {
			operator, _ := featureAgeFixture(t)
			request := ExportRequest{Source: "age:source", Target: "age:target", Selectors: store.Selectors{"env": "prod"}, OnConflict: "fail"}
			if explicit {
				request.Keys = []string{"TOKEN"}
			}
			operator.Confirm = func(result OperatorResult) error {
				// Deterministic post-confirm/pre-read writer changes which exact labels win.
				return (backend.AgeTransaction{Config: operator.Age, Reference: "age:source"}).Apply([]store.Mutation{{Kind: store.MutationDelete, Key: "TOKEN", Labels: map[string]string{"env": "prod"}}})
			}
			if _, err := operator.Export(context.Background(), request); err != secure.ErrConflict {
				t.Fatal("selection drift accepted")
			}
			snapshot, err := operator.Age.Read("age:target")
			if err != nil {
				t.Fatal(err)
			}
			defer snapshot.Close()
			if len(snapshot.Records) != 0 {
				t.Fatal("destination mutated")
			}
		})
	}
}
func TestAgeAuditActionSchema(t *testing.T) {
	for _, action := range []store.OperatorAction{store.ActionAgeInit, store.ActionAgeRekey} {
		event := store.AuditEvent{Version: store.MetadataVersion, Time: time.Now().UTC(), Action: action, Target: "age:test", Outcome: store.AuditSuccess}
		if !validAuditEvent(event) {
			t.Fatal("age action rejected")
		}
		event.Keys = []string{"TOKEN"}
		if validAuditEvent(event) {
			t.Fatal("age action accepted excess metadata")
		}
	}
}

func TestAgeStoragePathCollisions(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"age:team", "age:team", true},
		{"age:team", "keychain:team", false},
		{"age:team", "pass:team", false},
		{"keychain:team", "libsecret:team", true},
	} {
		first, err := storagePath(dir, tc.a)
		if err != nil {
			t.Fatal(tc.a, err)
		}
		second, err := storagePath(dir, tc.b)
		if err != nil {
			t.Fatal(tc.b, err)
		}
		if (first == second) != tc.same {
			t.Fatalf("%s and %s: storage collision mismatch", tc.a, tc.b)
		}
	}
}
