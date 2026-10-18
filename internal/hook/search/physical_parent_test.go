package search

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestConfigNativePrefixes(t *testing.T) {
	for _, name := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(name, "")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	config := ""
	for _, selector := range required {
		config += "--iglob=!" + selector + "\n"
	}
	for _, prefix := range []string{"~", "$HOME", "${HOME}"} {
		name := filepath.Join(prefix, "settings")
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(config), 0600); err != nil {
			t.Fatal(err)
		}
		if status, _ := Config(name, root, home); status != 0 {
			t.Errorf("literal native config %q: status=%d", name, status)
		}
	}
}

func TestGrepPhysicalParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	for _, name := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(name, "")
	}
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{filepath.Join(home, ".aws", "inner"), filepath.Join(work, "inner"), filepath.Join(root, "public", "inner")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"credentials", "inner/.env"} {
		if err := os.WriteFile(filepath.Join(home, ".aws", filepath.FromSlash(name)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{"lnk", filepath.Join(home, ".aws", "inner")},
		{"public-link", filepath.Join(root, "public", "inner")},
	} {
		if err := os.Symlink(link.target, filepath.Join(work, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	config := "--hidden\n"
	for _, selector := range required {
		config += "--iglob=!" + selector + "\n"
	}
	if err := os.WriteFile(filepath.Join(work, "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aws", "config"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if status, _ := Config("lnk/../config", work, home); status != 2 {
		t.Errorf("physical credential config certified: status=%d", status)
	}
	for _, tc := range []struct {
		name, path, glob string
		deny             bool
	}{
		{"directory_selector", work, "lnk/../inner/**", true},
		{"path_parent", "lnk/..", "cred*", true},
		{"path_prefix_parent", "lnk/..", "inner/**", true},
		{"public_directory_selector", work, "public-link/../inner/**", false},
		{"public_path_parent", "public-link/..", "*.md", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := ToolGrep(tc.path, tc.glob, "", "content", work, home); (reason != "") != tc.deny {
				t.Errorf("reason=%q, want deny=%v", reason, tc.deny)
			}
		})
	}
}
