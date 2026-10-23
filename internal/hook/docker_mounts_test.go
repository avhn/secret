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

func TestDockerPhysicalParentsBothAdapters(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{filepath.Join(home, ".aws", "inner"), filepath.Join(work, "public", "inner")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{"alias", filepath.Join(home, ".aws", "inner")},
		{"public-alias", filepath.Join(work, "public", "inner")},
	} {
		if err := os.Symlink(link.target, filepath.Join(work, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "RIPGREP_CONFIG_PATH"} {
		t.Setenv(key, "")
	}
	// Envelopes are input only. The aliases and missing credential-name leaves
	// are disposable metadata, never candidate container commands to execute.
	for _, engine := range []string{"docker", "podman"} {
		for _, tc := range []struct {
			args []string
			deny bool
		}{
			{[]string{"run", "-v", "./alias/..:/input:ro", "alpine", "cat", "/input/credentials"}, true},
			{[]string{"run", "--mount=type=bind,source=./alias/..,target=/input", "alpine", "cat", "/input/config"}, true},
			{[]string{"run", "--mount=type=bind,src=./,dst=/input", "alpine", "cat", "/input/alias/../credentials"}, true},
			{[]string{"run", "-v", "./:/input:ro", "-w", "/input/alias/..", "alpine", "cat", "credentials"}, true},
			{[]string{"run", "-v", "./:/input:ro", "--workdir=/input/public-alias/..", "alpine", "cat", "credentials"}, false},
			{[]string{"run", "-v", "./public-alias/..:/input:ro", "alpine", "cat", "/input/credentials"}, false},
			{[]string{"run", "-v", "./:/input:ro", "alpine", "cat", "/input/public-alias/../credentials"}, false},
			{[]string{"cp", "synthetic:" + work + "/alias/../credentials", "-"}, true},
			{[]string{"cp", "synthetic:" + work + "/public-alias/../credentials", "-"}, false},
		} {
			argv := append([]string{engine}, tc.args...)
			for _, host := range []string{"claude", "codex"} {
				for _, command := range []any{argv, audit26Shell(argv)} {
					body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": work, "tool_input": map[string]any{"command": command}})
					if err != nil {
						t.Fatal(err)
					}
					var output bytes.Buffer
					if err := Decide(host, bytes.NewReader(body), &output); err != nil {
						t.Fatal(err)
					}
					if got := strings.Contains(output.String(), `"permissionDecision":"deny"`); got != tc.deny {
						t.Errorf("%s command=%q deny=%v want=%v", host, command, got, tc.deny)
					}
				}
			}
		}
	}
}
