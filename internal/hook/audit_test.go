package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuditEnvelopes exercises every retained audit reproducer through the
// actual host decoder, scoped paths, shell dispatch and denial renderer.
func TestAuditEnvelopes(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hook/audit-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Fixtures [][3]string
		Cases    []struct {
			Name, Tool, CWD string
			Fields          map[string]any
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			dir := t.TempDir()
			for _, entry := range corpus.Fixtures {
				name := filepath.Join(dir, filepath.FromSlash(entry[0]))
				if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
					t.Fatal(err)
				}
				switch entry[1] {
				case "dir":
					err = os.MkdirAll(name, 0700)
				case "file":
					err = os.WriteFile(name, nil, 0600)
				case "link":
					err = os.Symlink(entry[2], name)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", filepath.Join(dir, "home"))
			t.Setenv("RIPGREP_CONFIG_PATH", filepath.Join(root, "examples/ripgreprc"))
			body, err := json.Marshal(map[string]any{"tool_name": tc.Tool, "cwd": strings.ReplaceAll(tc.CWD, "@TMP@", filepath.ToSlash(dir)), "tool_input": tc.Fields})
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"claude", "codex"} {
				if host == "codex" && tc.Tool == "Grep" {
					continue
				}
				var output bytes.Buffer
				if err := Decide(host, bytes.NewReader(body), &output); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(output.String(), `"permissionDecision":"deny"`) {
					t.Errorf("%s audit call allowed: %s", host, body)
				}
			}
		})
	}
}

type audit2Corpus struct {
	Fixtures [][3]string
	Cases    []struct {
		Name, Tool, CWD string
		Deny            bool
		Fields          map[string]any
	}
}

// audit2Fixture creates only synthetic metadata and disposable git history.
// The analyzer itself never starts git or reads the committed object contents.
func audit2Fixture(t *testing.T) (string, audit2Corpus) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is required for the audit2 history fixture")
	}
	data, err := os.ReadFile("testdata/audit2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus audit2Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, entry := range corpus.Fixtures {
		name := filepath.Join(dir, filepath.FromSlash(entry[0]))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		switch entry[1] {
		case "dir":
			err = os.MkdirAll(name, 0700)
		case "file":
			err = os.WriteFile(name, []byte("SYNTHETIC=fixture\n"), 0600)
		case "link":
			err = os.Symlink(filepath.FromSlash(entry[2]), name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(dir, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	for _, repo := range []string{"r", "r2"} {
		root := filepath.Join(dir, "w", repo)
		run := func(args ...string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, git, append([]string{"--no-pager"}, args...)...)
			cmd.Stdin = nil
			cmd.WaitDelay = time.Second
			cmd.Dir = root
			// Do not inherit git config, hooks, signing or real repository selectors.
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_PAGER=cat", "PAGER=cat", "GIT_AUTHOR_NAME=Synthetic", "GIT_AUTHOR_EMAIL=synthetic@example.invalid", "GIT_COMMITTER_NAME=Synthetic", "GIT_COMMITTER_EMAIL=synthetic@example.invalid"}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("synthetic git %v: %v\n%s", args, err, output)
			}
		}
		run("init", "--quiet")
		if repo == "r2" {
			if err := os.WriteFile(filepath.Join(root, ".env"), []byte("SYNTHETIC=deleted\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		run("add", ".")
		run("-c", "commit.gpgsign=false", "-c", "core.hooksPath="+home, "commit", "--quiet", "-m", "synthetic initial")
		if repo == "r2" {
			if err := os.Remove(filepath.Join(root, ".env")); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("synthetic second revision\n"), 0600); err != nil {
			t.Fatal(err)
		}
		run("add", "-A")
		run("-c", "commit.gpgsign=false", "-c", "core.hooksPath="+home, "commit", "--quiet", "-m", "synthetic second")
	}
	return dir, corpus
}

func TestAudit2Envelopes(t *testing.T) {
	dir, corpus := audit2Fixture(t)
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fields := make(map[string]any)
			for key, value := range tc.Fields {
				if text, ok := value.(string); ok {
					value = strings.ReplaceAll(text, "@TMP@", filepath.ToSlash(dir))
				}
				fields[key] = value
			}
			body, err := json.Marshal(map[string]any{"tool_name": tc.Tool, "cwd": filepath.Join(dir, "w", filepath.FromSlash(tc.CWD)), "tool_input": fields})
			if err != nil {
				t.Fatal(err)
			}
			requireBashEnvelope(t, body)
			for _, host := range []string{"claude", "codex"} {
				if host == "codex" && tc.Tool == "Grep" || host == "claude" && tc.Tool == "apply_patch" {
					continue
				}
				var output bytes.Buffer
				if err := Decide(host, bytes.NewReader(body), &output); err != nil {
					t.Fatal(err)
				}
				denied := strings.Contains(output.String(), `"permissionDecision":"deny"`)
				if denied != tc.Deny {
					t.Errorf("%s deny=%v want %v: %s", host, denied, tc.Deny, body)
				}
			}
		})
	}
}
