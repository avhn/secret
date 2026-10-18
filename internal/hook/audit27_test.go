package hook

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAudit27ArgvPreparationBudget(t *testing.T) {
	check := audit26EnvelopeCheck(t)
	for _, tc := range []struct {
		argv []string
		deny bool
	}{
		{[]string{"printf", "%s", strings.Repeat("p", 8179)}, false},
		{[]string{"printf", "%s", strings.Repeat("p", 8182)}, true},
		{[]string{"printf", "%s", strings.Repeat("é", 5000)}, true},
		{[]string{"printf", "%s", "", "public\n"}, false},
		{[]string{"bash", "-c", "cat > notes.md <<'TEXT'\n" + strings.Repeat("public\n", 2000) + "TEXT"}, false},
	} {
		check(t, tc.argv, tc.deny)
	}
}

func TestAudit27PatchBothAdapters(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, host := range []string{"claude", "codex"} {
		for _, tc := range []struct {
			body string
			deny bool
		}{
			{"*** Update File: public.txt\n@@\n-old\n+new\n*** End of File", false},
			{"*** Update File: public.txt\n*** End of File", true},
			{"*** Update File: .env\n@@\n+synthetic\n*** End of File", true},
		} {
			payload, err := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": root, "tool_input": map[string]string{"command": "*** Begin Patch\n" + tc.body + "\n*** End Patch"}})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := Decide(host, bytes.NewReader(payload), &output); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(output.String(), `"permissionDecision":"deny"`); got != tc.deny {
				t.Errorf("%s deny=%v want=%v", host, got, tc.deny)
			}
		}
	}
}
