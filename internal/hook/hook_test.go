package hook

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
)

// TestDecide compares the host JSON shape for synthetic paths and empty input.
func TestDecide(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cases use Unix host cwds; the Windows hook adapter is M5e")
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
