package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
