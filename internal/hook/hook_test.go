package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestDecide compares the host JSON shape for synthetic paths and empty input.
func TestDecide(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix envelope fixtures; native M5a file/patch and shell-denial tests run separately")
	}
	cases := []struct{ name, host, payload, reason string }{
		{"read protected", "claude", `{"tool_name":"Read","cwd":"/synthetic","tool_input":{"file_path":".env"}}`, "file access targets a protected store"},
		{"read safe", "claude", `{"tool_name":"Read","cwd":"/synthetic","tool_input":{"file_path":"src/a.go"}}`, ""},
		{"notebook protected", "claude", `{"tool_name":"NotebookEdit","cwd":"/synthetic","tool_input":{"notebook_path":".secrets/data.ipynb"}}`, "file access targets a protected store"},
		{"multi edit protected", "claude", `{"tool_name":"MultiEdit","cwd":"/synthetic","tool_input":{"file_path":".env"}}`, "file access targets a protected store"},
		{"glob protected root", "claude", `{"tool_name":"Glob","cwd":"/synthetic","tool_input":{"path":".secrets","pattern":"*.secret"}}`, "file access targets a protected store"},
		{"patch", "codex", `{"tool_name":"apply_patch","cwd":"/synthetic","tool_input":{"command":"*** Add File: .netrc\n+synthetic"}}`, "patch targets a protected store"},
		{"patch workdir", "codex", `{"tool_name":"apply_patch","cwd":"/synthetic","tool_input":{"workdir":"nested","command":"*** Begin Patch\n*** Add File: ../.netrc\n*** End Patch"}}`, "patch targets a protected store"},
		{"invalid cwd", "codex", `{"tool_name":"apply_patch","cwd":"relative","tool_input":{"command":"*** Begin Patch\n*** Add File: safe.go\n*** End Patch"}}`, "command too complex to analyse for secret access; split it or use secret run"},
		{"malformed", "claude", "bad", "command too complex to analyse for secret access; split it or use secret run"},
		{"malformed argv", "claude", `{"tool_name":"Bash","cwd":"/synthetic","tool_input":{"command":["cat",1]}}`, "command too complex to analyse for secret access; split it or use secret run"},
		{"safe argv", "claude", `{"tool_name":"Bash","cwd":"/synthetic","tool_input":{"command":["cat","src/a.go"]}}`, ""},
		{"literal shell-looking argv", "claude", `{"tool_name":"Bash","cwd":"/synthetic","tool_input":{"command":["printf","%s","$(cat .env); cat .env"]}}`, ""},
		{"empty", "claude", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := Decide(tc.host, strings.NewReader(tc.payload), &out); err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if out.Len() != 0 {
					t.Fatalf("unexpected decision: %s", out.String())
				}
				return
			}
			expected := `"permissionDecisionReason":"` + tc.reason
			if !strings.Contains(out.String(), expected) || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
				t.Fatalf("unexpected denial: %s", out.String())
			}
		})
	}
}

// TestNotebookEditPaths checks the authoritative notebook target against a
// separate Git directory. An unrelated file_path is not an additional target.
func TestNotebookEditPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix envelope fixtures; native M5a file/patch and shell-denial tests run separately")
	}
	root := t.TempDir()
	gitdir := filepath.Join(root, "metadata")
	for _, dir := range []string{filepath.Join(gitdir, "objects"), filepath.Join(gitdir, "refs")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gitdir, "HEAD"), []byte("ref: refs/heads/main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, notebook, file string
		deny                 bool
	}{
		{"unrelated file path protected", "safe.ipynb", filepath.Join(gitdir, "hooks/pre-commit"), false},
		{"notebook path protected", filepath.Join(gitdir, "hooks/pre-commit"), "safe.ipynb", true},
		{"both paths safe", "safe.ipynb", "safe.go", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(map[string]any{"tool_name": "NotebookEdit", "cwd": root, "tool_input": map[string]string{"notebook_path": tc.notebook, "file_path": tc.file}})
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Decide("claude", bytes.NewReader(body), &out); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(out.String(), `"permissionDecision":"deny"`); got != tc.deny {
				t.Errorf("denial=%s, want denial=%v", out.String(), tc.deny)
			}
		})
	}
}
