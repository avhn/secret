package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Replay only guard envelopes. Fixture files are synthetic, and candidate
// readers, credential printers and interpreters are never launched.
func TestAudit21Envelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit21.json")
}

func testAuditEnvelopes(t *testing.T, filename string) {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	data = bytes.ReplaceAll(data, []byte("@TMP@"), []byte(filepath.ToSlash(root)))
	fileRoot := filepath.ToSlash(root)
	if !strings.HasPrefix(fileRoot, "/") {
		fileRoot = "/" + fileRoot
	}
	data = bytes.ReplaceAll(data, []byte("@FILE_TMP@"), []byte(fileRoot))
	var corpus struct {
		Fixtures [][3]string
		Cases    []struct {
			Name    string
			Command string
			Tool    string
			Fields  map[string]string
			Deny    bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, entry := range corpus.Fixtures {
		name := filepath.Join(root, filepath.FromSlash(entry[0]))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(entry[2]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "RIPGREP_CONFIG_PATH"} {
		t.Setenv(key, "")
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			for _, host := range []string{"claude", "codex"} {
				tool, fields := tc.Tool, tc.Fields
				if tool == "" {
					tool, fields = "Bash", map[string]string{"command": tc.Command}
				}
				body, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": filepath.Join(root, "work"), "tool_input": fields})
				if err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				if err := Decide(host, bytes.NewReader(body), &output); err != nil {
					t.Fatal(err)
				}
				if deny := strings.Contains(output.String(), `"permissionDecision":"deny"`); deny != tc.Deny {
					t.Errorf("%s deny=%v want=%v: %s", host, deny, tc.Deny, output.String())
				}
			}
		})
	}
}
