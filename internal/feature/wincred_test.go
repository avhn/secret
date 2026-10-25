package feature

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestWincredNamesOnlyInterfaces(t *testing.T) {
	dir := testutil.TempDir(t)
	ref := "wincred:synthetic"
	path, err := store.ManifestPath(dir, ref)
	if err != nil {
		t.Fatal(err)
	}
	records := []store.ManifestRecord{
		{Key: "TOKEN", Labels: map[string]string{}, Account: "0123456789abcdef0123456789abcdef"},
		{Key: "TOKEN", Labels: map[string]string{"env": "test"}, Account: "fedcba9876543210fedcba9876543210"},
	}
	if err := store.WithWriteLock(dir, func() error { return store.PublishManifestLocked(path, "wincred", records) }); err != nil {
		t.Fatal(err)
	}
	// A plaintext-looking legacy sibling must not be used for provider metadata.
	if err := testutil.WriteFile(filepath.Join(dir, "synthetic.keys"), []byte("WRONG=synthetic-value-sentinel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err := ReadMetadata(ref, dir)
	if err != nil || metadata.Backend != "wincred" || len(metadata.Records) != 2 {
		t.Fatal("wincred metadata unavailable")
	}
	inventory, err := LoadInventory([]string{ref}, dir, store.Selectors{"env": "test"})
	if err != nil || len(inventory.Stores) != 1 || len(inventory.Stores[0].Records) != 1 || inventory.Stores[0].Records[0].Account != records[1].Account {
		t.Fatal("names-only label selection failed")
	}
	data, err := json.Marshal(inventory)
	if err != nil || bytes.Contains(data, []byte("synthetic-value-sentinel")) || bytes.Contains(data, []byte(`"value"`)) {
		t.Fatal("non-metadata inventory output")
	}
	candidates, err := Complete(CompletionRequest{Flag: "reference"}, []store.Metadata{metadata})
	if err != nil || !reflect.DeepEqual(candidates, []string{ref}) {
		t.Fatal("wincred completion failed")
	}
	if !validAuditEvent(store.AuditEvent{Version: store.MetadataVersion, Time: time.Now(), Action: store.ActionRotate, Target: ref, Keys: []string{"TOKEN"}, Outcome: store.AuditSuccess}) {
		t.Fatal("wincred names-only audit identity rejected")
	}
	server, err := NewMCPServer(MCPConfig{Enabled: true, Directory: dir, Stores: []string{ref}})
	if err != nil {
		t.Fatal("wincred MCP allowlist rejected")
	}
	responses, output, err := mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "show", map[string]any{"reference": ref, "selectors": map[string]string{"env": "test"}}))
	if err != nil || len(responses) != 2 || responses[1].Error != nil || !bytes.Contains(output, []byte("TOKEN")) || bytes.Contains(output, []byte("synthetic-value-sentinel")) {
		t.Fatal("wincred metadata MCP failed")
	}
	for _, invalid := range []string{"wincred:", "wincred:../synthetic", "wincred:synthetic:other"} {
		if _, err := ReadMetadata(invalid, dir); err == nil {
			t.Fatal("malformed metadata reference accepted")
		}
	}
}

func TestBackendStoragePathCollisions(t *testing.T) {
	directory := testutil.TempDir(t)
	for _, tc := range []struct {
		left, right string
		collision   bool
	}{
		{"keychain:synthetic", "libsecret:synthetic", true},
		{"pass:synthetic", "libsecret:synthetic", false},
		{"wincred:synthetic", "libsecret:synthetic", false},
		{"pass:synthetic", "wincred:synthetic", false},
		{"age:synthetic", "wincred:synthetic", false},
		{"age:synthetic", "pass:synthetic", false},
	} {
		left, leftErr := storagePath(directory, tc.left)
		right, rightErr := storagePath(directory, tc.right)
		if leftErr != nil || rightErr != nil || (left == right) != tc.collision {
			t.Fatalf("incorrect storage collision for %s and %s", tc.left, tc.right)
		}
	}
}
