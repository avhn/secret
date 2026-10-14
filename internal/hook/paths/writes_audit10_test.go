package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSeparateGitDirectoryWriteTargets(t *testing.T) {
	root := t.TempDir()
	gitDir := filepath.Join(root, "separate-gitdir")
	for _, dir := range []string{"objects", "refs"} {
		if err := os.MkdirAll(filepath.Join(gitDir, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(gitDir, "config"), filepath.Join(gitDir, "hooks", "pre-commit"), filepath.Join(gitDir, "refs", "heads", "test"), "~someuser/.gitconfig"} {
		if !ConfigWriteProtected(name, root, "", root, "", "") {
			t.Errorf("unprotected: %q", name)
		}
	}
	if ConfigWriteProtected(filepath.Join(root, "ordinary", "config"), root, "", root, "", "") {
		t.Error("ordinary write target denied")
	}
}
