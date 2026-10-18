package paths_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook"
	"github.com/avhn/secret/internal/hook/paths"
)

func audit27PathsFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	return home, work
}

func TestAudit27GitConfigDirectoryTargets(t *testing.T) {
	home, work := audit27PathsFixture(t)
	xdg := filepath.Join(filepath.Dir(home), "xdg")
	gitdir := filepath.Join(filepath.Dir(home), "gitdir")
	for _, dir := range []string{filepath.Join(home, ".config", "git"), filepath.Join(xdg, "git"), gitdir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, ".git"), []byte("gitdir: ../gitdir\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitdir, "HEAD"), []byte("ref: refs/heads/synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(home, ".config", "git"), filepath.Join(xdg, "git"), gitdir} {
		for _, suffix := range []string{"", "/", "/config", "/hooks/pre-commit"} {
			if !paths.ConfigWriteProtected(filepath.ToSlash(name)+suffix, work, "", home, xdg, "") {
				t.Errorf("Git directory target not protected: %s%s", name, suffix)
			}
		}
	}
	for _, name := range []string{filepath.Join(home, ".config", "git-public"), filepath.Join(xdg, "git-public"), gitdir + "-public", filepath.Join(work, "public")} {
		if paths.ConfigWriteProtected(name, work, "", home, xdg, "") {
			t.Errorf("ordinary target protected: %s", name)
		}
	}
}

func TestAudit27XDGPathResolution(t *testing.T) {
	home, work := audit27PathsFixture(t)
	for _, xdg := range []string{"", filepath.Join(home, ".config"), filepath.Join(filepath.Dir(home), "xdg")} {
		t.Setenv("XDG_CONFIG_HOME", xdg)
		root := xdg
		if root == "" {
			root = filepath.Join(home, ".config")
		}
		for _, prefix := range []string{"$XDG_CONFIG_HOME/", "${XDG_CONFIG_HOME}/"} {
			for _, suffix := range []string{"git/config", "git/hooks/pre-commit", "gcloud/credentials.db", "public/notes.txt"} {
				name := prefix + suffix
				want := filepath.Join(root, filepath.FromSlash(suffix))
				if got := filepath.Clean(paths.Resolve(name, work, "", home)); got != want {
					t.Errorf("resolve %s with XDG=%q: got=%s want=%s", name, xdg, got, want)
				}
				if got := paths.Protected(name, work, "", home); got != paths.Protected(want, work, "", home) {
					t.Errorf("protection differs from expanded target: %s", name)
				}
			}
			if !paths.ConfigWriteProtected(prefix+"git", work, "", home, xdg, "") {
				t.Errorf("XDG directory target not protected: %s", prefix)
			}
		}
	}
	// The write classifier's effective XDG argument can differ from the hook's
	// environment after a command-local assignment.
	local := filepath.Join(filepath.Dir(home), "local-xdg")
	if !paths.ConfigWriteProtected("$XDG_CONFIG_HOME/git", work, "", home, local, "") {
		t.Error("command-local XDG target lost during normalization")
	}
}

func TestAudit27XDGFileTools(t *testing.T) {
	home, work := audit27PathsFixture(t)
	for _, xdg := range []string{"", filepath.Join(home, ".config"), filepath.Join(filepath.Dir(home), "xdg")} {
		t.Setenv("XDG_CONFIG_HOME", xdg)
		root := xdg
		if root == "" {
			root = filepath.Join(home, ".config")
		}
		for _, tool := range []string{"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"} {
			for _, prefix := range []string{"$XDG_CONFIG_HOME/", "${XDG_CONFIG_HOME}/"} {
				for _, target := range []struct {
					name string
					deny bool
				}{
					{"gcloud/credentials.db", xdg == "" || xdg == filepath.Join(home, ".config")},
					{"git/config", tool != "Read"},
					{"git/hooks/pre-commit", tool != "Read"},
					{"public/notes.txt", false},
				} {
					for _, name := range []string{prefix + target.name, filepath.Join(root, filepath.FromSlash(target.name))} {
						field := "file_path"
						if tool == "NotebookEdit" {
							field = "notebook_path"
						}
						data, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": work, "tool_input": map[string]any{field: name}})
						if err != nil {
							t.Fatal(err)
						}
						for _, host := range []string{"claude", "codex"} {
							var out bytes.Buffer
							if err := hook.Decide(host, bytes.NewReader(data), &out); err != nil {
								t.Fatal(err)
							}
							if deny := out.Len() != 0; deny != target.deny {
								t.Errorf("%s %s %s XDG=%q: deny=%v want=%v", host, tool, name, xdg, deny, target.deny)
							}
						}
					}
				}
			}
		}
	}
}
