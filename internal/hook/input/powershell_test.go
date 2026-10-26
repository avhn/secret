package input

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodePowerShell(t *testing.T) {
	cwd, _ := json.Marshal(t.TempDir())
	prefix := `{"tool_name":"PowerShell","cwd":` + string(cwd) + `,"tool_input":`
	body := func(fields string) string { return prefix + fields + `}` }
	command := func(source string) string {
		raw, err := json.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		return body(`{"command":` + string(raw) + `}`)
	}
	ordinary := command("Write-Output 'synthetic'")
	cases := []struct {
		name, data string
		valid      bool
	}{
		{"string", ordinary, true},
		{"empty string", command(""), true},
		{"missing", body(`{}`), false},
		{"null", body(`{"command":null}`), false},
		{"number", body(`{"command":1}`), false},
		{"boolean", body(`{"command":true}`), false},
		{"object", body(`{"command":{}}`), false},
		{"argv", body(`{"command":["Write-Output","synthetic"]}`), false},
		{"empty argv", body(`{"command":[]}`), false},
		{"duplicate command", body(`{"command":"first","command":"second"}`), false},
		{"escaped duplicate", body(`{"command":"first","comm` + `\` + `u0061nd":"second"}`), false},
		{"duplicate nested", body(`{"command":"synthetic","extra":{"key":1,"key":2}}`), false},
		{"duplicate tool", strings.Replace(ordinary, `"tool_name":"PowerShell"`, `"tool_name":"Bash","tool_name":"PowerShell"`, 1), false},
		{"invalid utf8 source", body("{\"command\":\"\xff\"}"), false},
		{"invalid utf8 metadata", body("{\"command\":\"synthetic\",\"description\":\"\xff\"}"), false},
		{"unpaired surrogate", body(`{"command":"\ud800"}`), false},
		{"paired surrogate", body(`{"command":"` + `\` + `ud800` + `\` + `udc00"}`), true},
		{"nul", body(`{"command":"\u0000"}`), false},
		{"source below ceiling", command(strings.Repeat("a", MaxPowerShellSourceBytes-1)), true},
		{"source at ceiling", command(strings.Repeat("a", MaxPowerShellSourceBytes)), true},
		{"source past ceiling", command(strings.Repeat("a", MaxPowerShellSourceBytes+1)), false},
		{"utf8 source at byte ceiling", command(strings.Repeat("é", MaxPowerShellSourceBytes/2)), true},
		{"utf8 source past byte ceiling", command(strings.Repeat("é", MaxPowerShellSourceBytes/2) + "a"), false},
		{"decoded escapes below ceiling", body(`{"command":"` + strings.Repeat(`\`+`u0061`, 7000) + `"}`), true},
		{"raw below ceiling", ordinary + strings.Repeat(" ", MaxPowerShellEnvelopeBytes-len(ordinary)-1), true},
		{"raw at ceiling", ordinary + strings.Repeat(" ", MaxPowerShellEnvelopeBytes-len(ordinary)), true},
		{"raw past ceiling", ordinary + strings.Repeat(" ", MaxPowerShellEnvelopeBytes-len(ordinary)+1), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Decode(strings.NewReader(tc.data))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
			if err != nil && err != ErrInvalid {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && e.Tool != "PowerShell" {
				t.Fatal("lost tool identity")
			}
		})
	}
}

func TestPowerShellBudgetsDoNotShrinkSharedBudgets(t *testing.T) {
	cwd, _ := json.Marshal(t.TempDir())
	for _, tool := range []string{"Bash", "Read", "apply_patch"} {
		t.Run(tool, func(t *testing.T) {
			body := `{"tool_name":"` + tool + `","cwd":` + string(cwd) + `,"tool_input":{"file_path":"public.txt","command":"` + strings.Repeat("a", MaxPowerShellSourceBytes+1) + `"}}`
			body += strings.Repeat(" ", MaxPowerShellEnvelopeBytes-len(body)+1)
			if _, err := Decode(strings.NewReader(body)); err != nil {
				t.Fatalf("shared source/envelope budgets changed: %v", err)
			}
		})
	}
}
