package hook

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/input"
)

const powershellDenialJSON = `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"PowerShell host contract is not enabled; use secret show FILE for masked names, or secret run -f FILE -- CMD; never disguise a denied command"}}` + "\n"

func powershellFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	return root, root
}

func powershellEnvelope(t *testing.T, tool, cwd string, fields map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": cwd, "tool_input": fields})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestPowerShellDefaultDeny(t *testing.T) {
	_, cwd := powershellFixture(t)
	for _, host := range []string{"claude", "codex", "unknown", ""} {
		for _, source := range []string{"", "Write-Output 'SYNTHETIC_SOURCE_MARKER'", "Get-Content .env # SYNTHETIC_SOURCE_MARKER", "(\nSYNTHETIC_SOURCE_MARKER"} {
			t.Run(host+"/"+source, func(t *testing.T) {
				body := powershellEnvelope(t, "PowerShell", cwd, map[string]any{
					"command": source, "shell": "powershell", "edition": "7.6", "workdir": "nested",
				})
				var out bytes.Buffer
				if err := Decide(host, bytes.NewReader(body), &out); err != nil {
					t.Fatal(err)
				}
				if out.String() != powershellDenialJSON {
					t.Fatalf("unexpected fixed denial: %q", out.String())
				}
				if strings.Contains(out.String(), "SYNTHETIC_SOURCE_MARKER") {
					t.Fatal("source appeared in hook output")
				}
			})
		}
	}
}

func TestPowerShellInvalidEnvelopeDeny(t *testing.T) {
	_, cwd := powershellFixture(t)
	quotedCWD, _ := json.Marshal(cwd)
	prefix := `{"tool_name":"PowerShell","cwd":` + string(quotedCWD) + `,"tool_input":`
	for _, fields := range []string{
		`{}`, `{"command":null}`, `{"command":3}`, `{"command":["SYNTHETIC_SOURCE_MARKER"]}`,
		`{"command":"SYNTHETIC_SOURCE_MARKER","command":"second"}`,
		"{\"command\":\"SYNTHETIC_SOURCE_MARKER\xff\"}",
		`{"command":"SYNTHETIC_SOURCE_MARKER\ud800"}`,
		`{"command":"` + strings.Repeat("a", input.MaxPowerShellSourceBytes+1) + `"}`,
		`{"command":"SYNTHETIC_SOURCE_MARKER","description":"` + strings.Repeat("a", input.MaxPowerShellEnvelopeBytes) + `"}`,
	} {
		for _, host := range []string{"claude", "codex"} {
			var out bytes.Buffer
			if err := Decide(host, strings.NewReader(prefix+fields+`}`), &out); err != nil {
				t.Fatal(err)
			}
			want := input.Deny("command too complex to analyse for secret access; split it or use secret run", false)
			if !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("invalid envelope did not retain fixed denial: %q", out.String())
			}
		}
	}
}

func TestUnknownShellContracts(t *testing.T) {
	_, cwd := powershellFixture(t)
	for _, tc := range []struct {
		tool    string
		fields  map[string]any
		windows bool
	}{
		{"UnrelatedTool", map[string]any{}, false},
		{"UnrelatedTool", map[string]any{"shell": "powershell"}, false},
		{"UnrecognizedShell", map[string]any{"command": "SYNTHETIC_SOURCE_MARKER"}, true},
		{"Shell", map[string]any{}, true},
		{"CMD", map[string]any{}, true},
		{"Cmd", map[string]any{}, true},
		{"cmd", map[string]any{}, true},
		{"cmd.exe", map[string]any{}, true},
		{"powershell", map[string]any{}, true},
		{"powershell.exe", map[string]any{}, true},
		{"pwsh", map[string]any{}, true},
		{"pwsh.exe", map[string]any{}, true},
		{"shell", map[string]any{}, true},
		{"exec_command", map[string]any{}, true},
		{"shell_command", map[string]any{}, true},
	} {
		for _, host := range []string{"claude", "codex", "unknown"} {
			t.Run(host+"/"+tc.tool, func(t *testing.T) {
				var out bytes.Buffer
				if err := Decide(host, bytes.NewReader(powershellEnvelope(t, tc.tool, cwd, tc.fields)), &out); err != nil {
					t.Fatal(err)
				}
				var want []byte
				if runtime.GOOS == "windows" && tc.windows {
					want = input.Deny("shell requests are unsupported on Windows", true)
				}
				if !bytes.Equal(out.Bytes(), want) {
					t.Fatalf("unknown tool contract changed: %q", out.String())
				}
			})
		}
	}
}

func TestPowerShellClassifierSeam(t *testing.T) {
	home, cwd := powershellFixture(t)
	original := powershellClassifier
	t.Cleanup(func() { powershellClassifier = original })
	calls := 0
	powershellClassifier = func(e input.Envelope, gotCWD, gotHome string) string {
		calls++
		if e.Tool != "PowerShell" || e.String("command") != "SYNTHETIC_SOURCE_MARKER" || gotCWD != cwd || gotHome != home {
			t.Error("adapter received unexpected validated inputs")
		}
		return ""
	}
	for _, host := range []string{"codex", "unknown", "claude"} {
		var out bytes.Buffer
		body := powershellEnvelope(t, "PowerShell", cwd, map[string]any{"command": "SYNTHETIC_SOURCE_MARKER"})
		if err := Decide(host, bytes.NewReader(body), &out); err != nil {
			t.Fatal(err)
		}
		want := powershellDenialJSON
		if runtime.GOOS == "windows" && host == "claude" {
			want = ""
		}
		if out.String() != want {
			t.Fatalf("unexpected seam decision for %s: %q", host, out.String())
		}
	}
	wantCalls := 0
	if runtime.GOOS == "windows" {
		wantCalls = 1
	}
	if calls != wantCalls {
		t.Fatalf("classifier calls=%d, want %d", calls, wantCalls)
	}
	// Neither unrelated tools nor invalid PowerShell envelopes reach the seam.
	for _, tc := range []struct {
		tool, cwd string
		fields    map[string]any
	}{
		{"UnrelatedTool", cwd, map[string]any{"shell": "powershell", "command": "SYNTHETIC_SOURCE_MARKER"}},
		{"PowerShell", cwd, map[string]any{}},
		{"PowerShell", cwd, map[string]any{"command": []string{"SYNTHETIC_SOURCE_MARKER"}}},
		{"PowerShell", "relative", map[string]any{"command": "SYNTHETIC_SOURCE_MARKER"}},
		{"PowerShell", filepath.Join(cwd, "nested"), map[string]any{"command": strings.Repeat("a", input.MaxPowerShellSourceBytes+1)}},
	} {
		var out bytes.Buffer
		if err := Decide("claude", bytes.NewReader(powershellEnvelope(t, tc.tool, tc.cwd, tc.fields)), &out); err != nil {
			t.Fatal(err)
		}
	}
	if reason := powershellDecision("claude", input.Envelope{Tool: "Bash"}, cwd, home); reason != powershellReason {
		t.Fatal("wrong dialect reached pending adapter")
	}
	if calls != wantCalls {
		t.Fatal("invalid or unrelated envelope reached classifier")
	}
	powershellClassifier = nil
	var out bytes.Buffer
	if err := Decide("claude", bytes.NewReader(powershellEnvelope(t, "PowerShell", cwd, map[string]any{"command": "SYNTHETIC_SOURCE_MARKER"})), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != powershellDenialJSON || calls != wantCalls {
		t.Fatal("production routing was not disabled after removing seam")
	}
}

func TestPowerShellClassifierPanicDeny(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("only Windows Claude can reach the classifier seam")
	}
	_, cwd := powershellFixture(t)
	original := powershellClassifier
	t.Cleanup(func() { powershellClassifier = original })
	powershellClassifier = func(input.Envelope, string, string) string {
		panic("SYNTHETIC_SOURCE_MARKER")
	}
	var out bytes.Buffer
	body := powershellEnvelope(t, "PowerShell", cwd, map[string]any{"command": "SYNTHETIC_SOURCE_MARKER"})
	if err := Decide("claude", bytes.NewReader(body), &out); err != nil {
		t.Fatal(err)
	}
	want := input.Deny("command too complex to analyse for secret access; split it or use secret run", false)
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("panic did not retain value-free denial: %q", out.String())
	}
}
