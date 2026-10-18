package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit28ConfiguredCase(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Run(key, func(t *testing.T) {
			target := filepath.Join(home, "custom", "profile.cfg")
			t.Setenv(key, target)
			for _, name := range []string{target, filepath.Join(home, "custom", "PROFILE.CFG"), filepath.Join(home, "Custom", "profile.cfg"), filepath.Join(home, "CUSTOM", "PROFILE.CFG")} {
				if !ConfiguredProtected(name, root, "", home, os.Getenv("KUBECONFIG")) || !Protected(name, root, "", home) {
					t.Errorf("%s mixed-case configured path was allowed", key)
				}
			}
			for _, dir := range []string{home, filepath.Join(home, "Custom"), filepath.Join(home, "CUSTOM")} {
				if !ConfiguredTreeProtected(dir, root, home, os.Getenv("KUBECONFIG")) {
					t.Errorf("%s mixed-case containing root was allowed", key)
				}
			}
			for _, dir := range []string{filepath.Join(home, "customized"), filepath.Join(home, "public"), filepath.Join(home, "custom", "profile.cfg.extra")} {
				if ConfiguredTreeProtected(dir, root, home, os.Getenv("KUBECONFIG")) {
					t.Errorf("%s unrelated root was protected", key)
				}
			}
			if Protected(filepath.Join(home, "Custom", "public.cfg"), root, "", home) {
				t.Fatal("unconfigured public file was protected")
			}
		})
	}
}

func TestAudit28ConfiguredCasePhysicalAlias(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	dir := filepath.Join(home, "custom")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	configured := filepath.Join(alias, "profile.cfg")
	if !ConfiguredProtected(filepath.Join(dir, "PROFILE.CFG"), root, "", home, configured) {
		t.Fatal("case-folded physical configured alias was allowed")
	}
	if !ConfiguredTreeProtected(dir, root, home, configured) {
		t.Fatal("configured alias containment was lost")
	}
	if !ConfiguredProtected(filepath.Join(dir, "PROFILE.CFG"), root, "", home, "", configured) {
		t.Fatal("singular configured witness did not fold physical alias case")
	}
	if !ConfiguredTreeProtected(dir, root, home, "", configured) {
		t.Fatal("singular configured witness containment was lost")
	}
}
