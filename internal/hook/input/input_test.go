package input

import (
	"strings"
	"testing"
)

// TestDecode covers supported field types, byte budgets, duplicates and suffixes.
func TestDecode(t *testing.T) {
	cases := []struct {
		name, body string
		valid      bool
	}{
		{"simple", `{"tool_name":"Read","cwd":"/synthetic","tool_input":{"file_path":".env"}}`, true},
		{"array", `{"tool_name":"Bash","tool_input":{"command":["cat",".env"]}}`, true},
		{"empty", "", false},
		{"missing tool", `{"tool_input":{}}`, false},
		{"trailing", `{"tool_name":"Read"}{}`, false},
		{"duplicate root", `{"tool_name":"Read","tool_name":"Bash"}`, false},
		{"duplicate nested", `{"tool_name":"Read","tool_input":{"file_path":"a","file_path":"b"}}`, false},
		{"field type", `{"tool_name":"Read","tool_input":{"file_path":5}}`, false},
		{"command type", `{"tool_name":"Bash","tool_input":{"command":["cat",3]}}`, false},
		{"control", `{"tool_name":"Read","tool_input":{"file_path":"a\u0000b"}}`, false},
		{"budget", strings.Repeat(" ", MaxBytes+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(tc.body))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

// TestDeny checks the exact PreToolUse denial envelope and fixed recovery text.
func TestDeny(t *testing.T) {
	want := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"file access targets a protected store; use secret show FILE for masked names, or secret run -f FILE -- CMD; never disguise a denied command"}}` + "\n"
	if got := string(Deny("file access targets a protected store", true)); got != want {
		t.Fatalf("unexpected denial envelope: %q", got)
	}
}

// FuzzDecode ensures arbitrary input cannot panic or bypass the decoder's budget.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(`{"tool_name":"Read","tool_input":{"file_path":"/synthetic/.env"}}`))
	f.Add([]byte(`{"tool_name":"Read","tool_name":"Write"}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Decode(strings.NewReader(string(data))) })
}
