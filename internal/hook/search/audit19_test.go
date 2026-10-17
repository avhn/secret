package search

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit19ConfiguredFilteredScope(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{home, filepath.Join(root, "selected"), filepath.Join(root, "public")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"selected/kube.yaml", "public/README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	for _, tc := range []struct {
		glob, typ, config string
		deny              bool
	}{
		{"*.yaml", "", "selected/kube.yaml", true},
		{"*.YAML", "", "selected/kube.yaml", true},
		{"*.yaml", "", filepath.Join(root, "selected", "kube.yaml"), true},
		{"*.yaml", "", "missing" + string(os.PathListSeparator) + "selected/kube.yaml", true},
		{"selected/**", "", "selected/kube.yaml", true},
		{"public/**", "", "selected/kube.yaml", false},
		{"*.md", "", "selected/kube.yaml", false},
		{"", "md", "public/README.md", true},
		{"*.yaml", "", "", false},
	} {
		t.Run(tc.glob+"/"+tc.typ+"/"+tc.config, func(t *testing.T) {
			if reason := FilteredScopeConfigured(root, tc.glob, tc.typ, root, home, tc.config); (reason != "") != tc.deny {
				t.Errorf("reason=%q, deny=%v", reason, tc.deny)
			}
		})
	}
	t.Run("physical alias", func(t *testing.T) {
		if err := os.Symlink(filepath.Join(root, "selected", "kube.yaml"), filepath.Join(root, "alias.yaml")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if reason := FilteredScopeConfigured(root, "alias.yaml", "", root, home, "selected/kube.yaml"); reason == "" {
			t.Fatal("configured credential alias certified as public")
		}
	})
}
