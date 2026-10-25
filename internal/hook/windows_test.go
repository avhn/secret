//go:build windows

package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/input"
)

func windowsHookFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_COMMON_DIR"} {
		t.Setenv(key, "")
	}
	return home, work
}

func windowsHookCheck(t *testing.T, tool, cwd string, fields map[string]any, reason string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": cwd, "tool_input": fields})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"claude", "codex"} {
		var out bytes.Buffer
		if err := Decide(host, bytes.NewReader(body), &out); err != nil {
			t.Fatal(err)
		}
		var expected []byte
		if reason != "" {
			expected = input.Deny(reason, reason != "command too complex to analyse for secret access; split it or use secret run")
		}
		if !bytes.Equal(out.Bytes(), expected) {
			t.Fatalf("%s %s decision=%s, want %s", host, tool, out.Bytes(), expected)
		}
	}
}

func TestWindowsShellRequestsDeny(t *testing.T) {
	_, work := windowsHookFixture(t)
	for _, command := range []any{
		"echo public", "Get-Content .env", "cmd /c type .env", "(", "", "true\n",
		[]string{"printf", "%s", "public"}, []string{"powershell.exe", "-Command", "Get-Content .env"},
		[]string{"bash.exe", "-c", "echo public"}, []string{"cmd.exe", "/c", "echo public"},
	} {
		windowsHookCheck(t, "Bash", work, map[string]any{"command": command}, windowsShellReason)
	}
	cwd, _ := json.Marshal(work)
	for _, fields := range []string{`{}`, `{"command":null}`, `{"command":["echo",null]}`, `{"command":3}`, `{"command":"echo public","command":"other"}`} {
		for _, host := range []string{"claude", "codex"} {
			var out bytes.Buffer
			body := `{"tool_name":"Bash","cwd":` + string(cwd) + `,"tool_input":` + fields + `}`
			if err := Decide(host, strings.NewReader(body), &out); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), input.Deny("command too complex to analyse for secret access; split it or use secret run", false)) {
				t.Fatalf("malformed shell envelope did not retain fixed denial: %s", out.Bytes())
			}
		}
	}
}

// Replay the retained shell corpus under the native all-shell-deny contract,
// without mutating any Unix expectation or creating/executing command fixtures.
func TestWindowsShellCorpusDeny(t *testing.T) {
	_, work := windowsHookFixture(t)
	files, err := filepath.Glob("../../testdata/hook/audit*.json")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "testdata/audit2.json")
	count := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var corpus struct {
			Cases []struct {
				Tool, Command string
				Fields        map[string]any
			}
		}
		if err := json.Unmarshal(data, &corpus); err != nil {
			t.Fatal(err)
		}
		for _, candidate := range corpus.Cases {
			if candidate.Tool != "" && candidate.Tool != "Bash" {
				continue
			}
			command, present := candidate.Fields["command"]
			if !present {
				if candidate.Command == "" {
					continue
				}
				command = candidate.Command
			}
			windowsHookCheck(t, "Bash", work, map[string]any{"command": command}, windowsShellReason)
			count++
		}
	}
	if count < 100 {
		t.Fatalf("shell corpus unexpectedly small: %d", count)
	}
}

func TestWindowsFileTools(t *testing.T) {
	home, work := windowsHookFixture(t)
	for _, tc := range []struct {
		name string
		deny bool
	}{
		{"public.txt", false}, {`src\public.go`, false}, {"src/public.go", false},
		{filepath.Join(work, "public.txt"), false}, {strings.ToUpper(filepath.Join(work, "public.txt")), false},
		{".env.example", false}, {".yarnrc.yml", false},
		{`.SeCrEtS\data`, true}, {`nested/.ENV`, true}, {`~\.yarnrc.yml`, true},
		{`$HOME\.yarnrc.yml`, true}, {`${HOME}/.yarnrc.yml`, true}, {filepath.Join(home, ".yarnrc.yml"), true},
		{`C:public.txt`, true}, {`\public.txt`, true}, {`/public.txt`, true},
		{`\\?\C:\public.txt`, true}, {`\\.\C:\public.txt`, true}, {`\??\C:\public.txt`, true},
		{`public.txt:stream`, true}, {`public.txt::$DATA`, true}, {`.env:stream`, true},
		{`NUL`, true}, {`con.txt`, true}, {`src\LPT1.txt`, true}, {`COM¹.log`, true},
		{`public.txt.`, true}, {`public.txt `, true}, {`missing\..\AUX`, true},
	} {
		for _, tool := range []string{"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"} {
			t.Run(tool+"/"+tc.name, func(t *testing.T) {
				field := "file_path"
				if tool == "NotebookEdit" {
					field = "notebook_path"
				}
				reason := ""
				if tc.deny {
					reason = "file access targets a protected store"
				}
				windowsHookCheck(t, tool, work, map[string]any{field: tc.name}, reason)
			})
		}
	}
	for _, tool := range []string{"Glob", "Grep"} {
		for _, name := range []string{`C:relative`, `public.txt:stream`, `NUL`, `\\?\C:\public`} {
			windowsHookCheck(t, tool, work, map[string]any{"path": name, "output_mode": "files_with_matches"}, "file access targets a protected store")
		}
	}
	for _, cwd := range []string{`C:relative`, `\rooted`, `\\?\C:\public`, work + ":stream"} {
		windowsHookCheck(t, "Read", cwd, map[string]any{"file_path": "public.txt"}, "command too complex to analyse for secret access; split it or use secret run")
	}
	// Explicit HOME retains precedence over USERPROFILE.
	t.Setenv("HOME", work)
	windowsHookCheck(t, "Read", work, map[string]any{"file_path": filepath.Join(work, ".yarnrc.yml")}, "file access targets a protected store")
	windowsHookCheck(t, "Read", work, map[string]any{"file_path": filepath.Join(home, ".yarnrc.yml")}, "")
}

func TestWindowsPatchTools(t *testing.T) {
	home, work := windowsHookFixture(t)
	for _, tc := range []struct{ name, reason string }{
		{`src\public.go`, ""}, {"src/public.go", ""}, {".env.example", ""},
		{`.AWS\CrEdEnTiAlS`, "patch targets a protected store"},
		{filepath.Join(home, ".yarnrc.yml"), "patch targets a protected store"},
		{`C:public`, "command too complex to analyse for secret access; split it or use secret run"},
		{`public:stream`, "command too complex to analyse for secret access; split it or use secret run"},
		{`\\?\C:\public`, "command too complex to analyse for secret access; split it or use secret run"},
		{`NUL.txt`, "command too complex to analyse for secret access; split it or use secret run"},
	} {
		for _, header := range []string{
			"*** Add File: " + tc.name + "\n+public",
			"*** Update File: " + tc.name + "\n@@\n-old\n+new",
			"*** Delete File: " + tc.name,
			"*** Update File: public.go\n*** Move to: " + tc.name + "\n@@\n-old\n+new",
			"*** Update File: " + tc.name + "\n*** Move to: public.go\n@@\n-old\n+new",
		} {
			windowsHookCheck(t, "apply_patch", work, map[string]any{"command": "*** Begin Patch\n" + header + "\n*** End Patch"}, tc.reason)
		}
	}
	for _, workdir := range []string{`C:relative`, `\rooted`, `public:stream`, `\\?\C:\public`} {
		windowsHookCheck(t, "apply_patch", work, map[string]any{"workdir": workdir, "command": "*** Begin Patch\n*** Delete File: public\n*** End Patch"}, "command too complex to analyse for secret access; split it or use secret run")
	}
}
