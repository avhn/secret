package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestM21PathRolesBothAdapters(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	for _, host := range []string{"claude", "codex"} {
		for _, tc := range []struct{ tool, field string }{
			{"Read", "file_path"}, {"Edit", "file_path"}, {"Write", "file_path"},
			{"MultiEdit", "file_path"}, {"NotebookEdit", "notebook_path"},
			{"Grep", "path"}, {"Glob", "path"}, {"Bash", "workdir"},
			{"apply_patch", "workdir"}, {"Bash", "cwd"},
		} {
			for _, value := range []string{strings.Repeat("a", 256), strings.Repeat("a/", 2048) + "public", strings.Repeat("界", 86) + "/../public"} {
				t.Run(host+"/"+tc.tool+"/"+tc.field, func(t *testing.T) {
					fields := map[string]any{"command": "true", "output_mode": "files_with_matches", tc.field: value}
					envelope := map[string]any{"tool_name": tc.tool, "cwd": root, "tool_input": fields}
					if tc.field == "cwd" {
						envelope["cwd"] = root + "/" + value
						delete(fields, tc.field)
					}
					data, err := json.Marshal(envelope)
					if err != nil {
						t.Fatal(err)
					}
					var output bytes.Buffer
					if err := Decide(host, bytes.NewReader(data), &output); err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(output.String(), `"permissionDecisionReason":"command too complex to analyse for secret access; split it or use secret run"`) {
						t.Fatalf("missing fixed recovery guidance: %s", output.String())
					}
				})
			}
		}
	}
}

func TestM21PatchRoutes(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, host := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			name, body string
			deny       bool
		}{
			{"valid add", "*** Add File: public\n+new", false},
			{"valid update", "*** Update File: public\n@@\n-old\n+new", false},
			{"implicit first chunk", "*** Update File: public\n old\n+new", false},
			{"implicit protected chunk", "*** Update File: .env\n old\n+new", true},
			{"blank context", "*** Update File: public\n@@\n\n+new", false},
			{"indented section", " *** Add File: public\n+new", false},
			{"invalid add", "*** Add File: public\n-old", true},
			{"invalid delete", "*** Delete File: public\n+new", true},
			{"invalid update", "*** Update File: public\n@@\nunprefixed", true},
			{"invalid move", "*** Update File: public\n*** Move to: next", true},
			{"control path", "*** Delete File: public\x01.txt", true},
			{"raw oversized path", "*** Delete File: " + strings.Repeat("a", 256) + "/../public", true},
			{"protected", "*** Add File: .env\n+synthetic", true},
		} {
			patch := "*** Begin Patch\n" + tc.body + "\n*** End Patch"
			for _, route := range []string{"native", "shell", "argv"} {
				t.Run(host+"/"+route+"/"+tc.name, func(t *testing.T) {
					tool := "apply_patch"
					var command any = patch
					if route != "native" {
						tool = "Bash"
						source := "apply_patch <<'PATCH'\n" + patch + "\nPATCH"
						command = source
						if route == "argv" {
							command = []string{"bash", "-c", source}
						}
					}
					data, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": root, "tool_input": map[string]any{"command": command}})
					if err != nil {
						t.Fatal(err)
					}
					var output bytes.Buffer
					if err := Decide(host, bytes.NewReader(data), &output); err != nil {
						t.Fatal(err)
					}
					if got := strings.Contains(output.String(), `"permissionDecision":"deny"`); got != tc.deny {
						t.Fatalf("deny=%v want=%v", got, tc.deny)
					}
				})
			}
		}
	}
}
