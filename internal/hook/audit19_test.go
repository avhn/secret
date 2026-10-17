package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Commands and paths in this corpus are analyzer input only. The fixture HOME,
// credential-shaped files and configured Kubernetes paths are all disposable.
func TestAudit19Envelopes(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hook/audit19.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data = bytes.ReplaceAll(data, []byte("@TMP@"), []byte(filepath.ToSlash(dir)))
	var corpus struct {
		Fixtures [][3]string
		Cases    []struct {
			Name, Tool, CWD string
			Deny            bool
			Fields          map[string]any
			Env             struct {
				KUBECONFIG      string
				KUBECONFIG_LIST []string
			}
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, entry := range corpus.Fixtures {
		name := filepath.Join(dir, filepath.FromSlash(entry[0]))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if entry[1] == "dir" {
			err = os.MkdirAll(name, 0700)
		} else {
			err = os.WriteFile(name, []byte(entry[2]), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	t.Setenv("KUBECONFIG", "")
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			config := tc.Env.KUBECONFIG
			if len(tc.Env.KUBECONFIG_LIST) > 0 {
				config = strings.Join(tc.Env.KUBECONFIG_LIST, string(os.PathListSeparator))
			}
			t.Setenv("KUBECONFIG", config)
			payload := func(fields map[string]any) []byte {
				t.Helper()
				body, err := json.Marshal(map[string]any{"tool_name": tc.Tool, "cwd": tc.CWD, "tool_input": fields})
				if err != nil {
					t.Fatal(err)
				}
				return body
			}
			for _, host := range []string{"claude", "codex"} {
				if host == "codex" && tc.Tool == "Grep" {
					continue
				}
				var output bytes.Buffer
				if err := Decide(host, bytes.NewReader(payload(tc.Fields)), &output); err != nil {
					t.Fatal(err)
				}
				if got := strings.Contains(output.String(), `"permissionDecision":"deny"`); got != tc.Deny {
					t.Errorf("%s deny=%v, want %v: %s", host, got, tc.Deny, output.String())
				}
			}
		})
	}
}
