//go:build windows

package feature

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsTrustedParentOperatorAndMCP(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "inherited"}[inherited], func(t *testing.T) {
			dir := testutil.TempDir(t)
			source := filepath.Join(dir, "synthetic.source")
			if err := testutil.WriteFile(source, []byte("TOKEN=synthetic-value-sentinel\n"), 0600); err != nil {
				t.Fatal(err)
			}
			testutil.TrustStoreParent(t, dir, inherited)
			provider := &operatorProvider{}
			confirmations := 0
			operator := Operator{SecretsDir: dir, Providers: map[string]backend.Provider{"wincred:synthetic": provider, "wincred:export": &operatorProvider{}, "wincred:copy": &operatorProvider{}}, Confirm: func(OperatorResult) error { confirmations++; return nil }}
			if _, err := operator.Import(context.Background(), ImportRequest{Source: "dotenv:" + source, Target: "wincred:synthetic"}); err != nil {
				t.Fatal(err)
			}
			// File-source export exercises the same opener separately from dotenv import.
			if _, err := operator.Export(context.Background(), ExportRequest{Source: "file:" + source, Target: "wincred:export", OnConflict: "fail"}); err != nil {
				t.Fatal(err)
			}
			if _, err := operator.Export(context.Background(), ExportRequest{Source: "wincred:export", Target: "wincred:copy", OnConflict: "fail"}); err != nil {
				t.Fatal(err)
			}
			reference := "file:" + source
			server, err := NewMCPServer(MCPConfig{Enabled: true, Stores: []string{reference}, Directory: dir})
			if err != nil {
				t.Fatal(err)
			}
			responses, output, err := mcpTestServe(t, server, mcpTestInitialize+mcpTestCall(1, "show", map[string]any{"reference": reference}))
			if err != nil || len(responses) != 2 || responses[1].Error != nil || !bytes.Contains(output, []byte("TOKEN")) || bytes.Contains(output, []byte("synthetic-value-sentinel")) {
				t.Fatal("names-only MCP failed or exposed value")
			}
			if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: reference, Key: "TOKEN"}, func() ([]byte, error) { return []byte("synthetic-rotated"), nil }); err != nil {
				t.Fatal(err)
			}
			if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRename, Reference: reference, Key: "TOKEN", NewKey: "RENAMED"}, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionDelete, Reference: reference, Key: "RENAMED"}, nil); err != nil {
				t.Fatal(err)
			}
			if confirmations != 6 {
				t.Fatal("operator skipped consent")
			}
			manifest, err := store.ManifestPath(dir, "wincred:synthetic")
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{source, manifest} {
				assertWindowsPrivate(t, path)
			}
			for _, reference := range []string{"wincred:export", "wincred:copy"} {
				path, err := store.ManifestPath(dir, reference)
				if err != nil {
					t.Fatal(err)
				}
				assertWindowsPrivate(t, path)
			}
			for _, value := range provider.reads {
				assertOperatorZeroed(t, value)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if file, err := openFeatureFile(root, filepath.Base(source)); err == nil {
				file.Close()
				t.Fatal("template/audit opener accepted trusted-only parent")
			}
			if validateFeatureDirectory(root, true) != secure.ErrPrivateFile {
				t.Fatal("private directory policy weakened")
			}
			alias := filepath.Join(filepath.Dir(dir), "alias")
			if err := os.Symlink(dir, alias); err != nil {
				t.Fatal(err)
			}
			if _, err := readOperatorFile(filepath.Join(alias, filepath.Base(source)), false); err == nil {
				t.Fatal("operator accepted final parent reparse point")
			}
		})
	}
}
