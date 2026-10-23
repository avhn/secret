package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit28GHConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "XDG_CONFIG_HOME", "GH_CONFIG_DIR"} {
		t.Setenv(key, "")
	}
	for _, key := range []string{"XDG_CONFIG_HOME", "GH_CONFIG_DIR"} {
		t.Run(key, func(t *testing.T) {
			dir := filepath.Join(root, "custom")
			t.Setenv(key, dir)
			target := GHHostsPath(key, dir)
			metadata := new(Metadata)
			for _, name := range []string{target, filepath.Join(filepath.Dir(target), "HOSTS.YML")} {
				if !Protected(name, root, "", home) || !metadata.Protected(name, root, "", home) || !metadata.LexicalProtected(name, root, home) {
					t.Errorf("configured gh target allowed: %s", name)
				}
			}
			// Even an absent credential file prevents certifying content searches.
			if !ConfiguredTreeProtected(dir, root, home, "") {
				t.Fatal("configured gh tree allowed")
			}
			for _, public := range []string{target + ".example", filepath.Join(dir, "public.yml"), filepath.Join(root, "other", "hosts.yml")} {
				if Protected(public, root, "", home) || metadata.Protected(public, root, "", home) {
					t.Errorf("public file protected: %s", public)
				}
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, key+"-alias")
			if err := os.Symlink(target, alias); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if !Protected(alias, root, "", home) || !new(Metadata).Protected(alias, root, "", home) {
				t.Fatal("dangling gh credential alias allowed")
			}
		})
	}
}
