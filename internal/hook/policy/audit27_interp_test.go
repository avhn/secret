package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/roles"
)

// Candidates are analyzed as source only, with disposable metadata and HOME.
func TestAudit27QualifiedDenoConstructors(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, member := range []string{"globalThis . Deno.Command", "globalThis.Deno . Command", "globalThis /* receiver */ . Deno /* member */ . Command", "globalThis.\nDeno.\nCommand"} {
		for _, tc := range []struct {
			executable, args string
			deny             bool
		}{
			{"gh", `"auth","token"`, true}, {"cat", `".env"`, true},
			{"cat", `"README.md"`, false}, {"echo", `"public"`, false},
		} {
			code := fmt.Sprintf(`new %s(%q,{args:[%s],stdout:"inherit"}).spawn()`, member, tc.executable, tc.args)
			for _, prefix := range []string{"", "env -- ", "timeout 5 "} {
				for _, source := range []string{
					prefix + "deno eval " + shellLiteral(code),
					prefix + "deno run --allow-run - <<'CODE'\n" + code + "\nCODE",
				} {
					if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
					}
				}
				argv := append(strings.Fields(prefix), "deno", "eval", code)
				if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != tc.deny {
					t.Errorf("argv %q: reason=%q want deny=%v", argv, reason, tc.deny)
				}
			}
		}
	}
	for _, code := range []string{
		`console.log('new globalThis . Deno.Command("gh",{args:["auth","token"]})')`,
		`// new globalThis . Deno.Command("gh",{args:["auth","token"]})`,
		`const args = ["gh","auth","token"]; console.log("globalThis . Deno.Command")`,
	} {
		if reason := AnalyzeArgv([]string{"deno", "eval", code}, work, home, check); reason != "" {
			t.Errorf("inert constructor %s: %s", code, reason)
		}
	}
}

func TestAudit27MissingInterpreterOperands(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, argv := range [][]string{
		{"python3", "-c"}, {"pypy3", "-c"}, {"ruby", "-e"}, {"ruby", "-E"},
		{"perl", "-E"}, {"node", "--eval"}, {"node", "--require"}, {"bun", "-e"},
		{"lua", "-e"}, {"php", "-r"}, {"Rscript", "-e"},
		{"python3", "-IBc"}, {"perl", "-0777wE"}, {"ruby", "-W0ne"},
		{"node", "-econsole.log(1)", "--require"}, {"bun", "run", "-e"},
	} {
		for _, prefix := range [][]string{nil, {"env", "--"}, {"timeout", "5"}} {
			words := append(append([]string(nil), prefix...), argv...)
			if reason := AnalyzeArgv(words, work, home, check); reason != roles.Indeterminate {
				t.Errorf("argv %q: reason=%q want indeterminate", words, reason)
			}
			if reason := Analyze(strings.Join(words, " "), work, home, check); reason != roles.Indeterminate {
				t.Errorf("shell %q: reason=%q want indeterminate", words, reason)
			}
		}
	}
	for _, argv := range [][]string{
		{"python3", "-c", ""}, {"ruby", "-e", ""}, {"perl", "-E", ""},
		{"node", "--eval="}, {"bun", "--eval="}, {"php", "-r", ""},
		{"ruby", "-W"}, {"ruby", "-0"}, {"perl", "-0"}, {"perl", "-l"},
		{"perl", "-i"}, {"perl", "-C"}, {"ruby", "-i"},
		{"perl", "-e", "print 1", "-F"}, {"perl", "-F"},
		{"perl", "-F,", "-e", "print 1"}, {"perl", "-F", "-eprint 1"},
		{"luajit", "-e", "print(1)", "-O"}, {"luajit", "-O"},
		{"luajit", "-O2", "-e", "print(1)"}, {"luajit", "-O", "-eprint(1)"},
		{"node", "public.js", "--require"}, {"ruby", "--", "-e"},
		{"python3", "-c", "print(1)"}, {"python3", "-c", "", "-W"},
		{"python3", "-cprint(1)", "-c"}, {"python3", "-m", "pytest", "-c"},
		{"python3", "-mpytest", "-c"},
	} {
		var quoted []string
		for _, word := range argv {
			quoted = append(quoted, shellLiteral(word))
		}
		if reason := AnalyzeArgv(argv, work, home, check); reason != "" {
			t.Errorf("complete/optional argv %q: %s", argv, reason)
		}
		if reason := Analyze(strings.Join(quoted, " "), work, home, check); reason != "" {
			t.Errorf("complete/optional shell %q: %s", argv, reason)
		}
	}
}

func TestAudit27InterpreterChildCwd(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, api := range []struct{ program, flag, source string }{
		{"php", "-r", `proc_open(["cat",%q],[0=>STDIN,1=>STDOUT,2=>STDERR],$pipes,%q);`},
		{"php", "-r", `proc_open(["cat",%q],[],$pipes,%q);`},
		{"php", "-r", `PROC_OPEN(["cat",%q],[0=>STDIN,1=>STDOUT,2=>STDERR],$pipes,%q);`},
		{"php", "-r", `Proc_Open(["cat",%q],[],$pipes,%q);`},
		{"php", "-r", `PROC_OPEN("cat %s",[1=>["pipe","w"],2=>STDERR],$pipes,%q);`},
		{"php", "-r", `Proc_Open("cat %s",[],$pipes,%q);`},
		{"php", "-r", `proc_open("cat %s",[1=>["pipe","w"],2=>STDERR],$pipes,%q);`},
		{"node", "-e", `require("child_process").spawnSync("cat",[%q],{cwd:%q,stdio:"inherit"})`},
		{"node", "-e", `require("child_process").execFileSync("cat",[%q],{"cwd":%q,stdio:"inherit"})`},
		{"node", "-e", `require("child_process").execSync("cat %s",{cwd:%q,stdio:"inherit"})`},
		{"bun", "-e", `Bun.spawnSync(["cat",%q],{cwd:%q,stdout:"inherit"})`},
	} {
		for _, tc := range []struct {
			file, dir string
			deny      bool
		}{
			{"credentials", filepath.Join(home, ".aws"), true},
			{"id_ed25519", filepath.Join(home, ".ssh"), true},
			{"config", filepath.Join(home, ".kube"), true},
			{"credentials", filepath.Join("..", "home", ".aws"), true},
			{"README.md", filepath.Join(home, ".aws"), false},
			{"README.md", work, false}, {"credentials", work, false},
		} {
			code := fmt.Sprintf(api.source, tc.file, filepath.ToSlash(tc.dir))
			stdin := code
			if api.program == "php" {
				stdin = "<?php\n" + code
			}
			for _, source := range []string{
				api.program + " " + api.flag + " " + shellLiteral(code),
				api.program + " " + api.flag + shellLiteral(code),
				"env -- " + api.program + " " + api.flag + shellLiteral(code),
				api.program + " <<'CODE'\n" + stdin + "\nCODE",
				api.program + " <<< " + shellLiteral(stdin),
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
				}
			}
			for _, argv := range [][]string{{api.program, api.flag, code}, {api.program, api.flag + code}} {
				if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != tc.deny {
					t.Errorf("argv %q: reason=%q want deny=%v", argv, reason, tc.deny)
				}
			}
		}
	}
}

func TestAudit27InterpreterCwdBoundaries(t *testing.T) {
	home, work, check := audit21Fixture(t)
	aws := fmt.Sprintf("%q", filepath.ToSlash(filepath.Join(home, ".aws")))
	for _, tc := range []struct {
		program, flag, code string
		deny                bool
	}{
		{"node", "-e", `spawnSync("cat",["credentials"],{other:{cwd:` + aws + `}})`, false},
		{"node", "-e", `spawnSync("cat",["credentials"],{label:"cwd",other:["{","}"]})`, false},
		{"node", "-e", `spawnSync("cat",["credentials"],{cwd:` + aws + `,cwd:"."})`, true},
		{"node", "-e", `spawnSync("cat",["credentials"],{cwd:unknown})`, true},
		{"node", "-e", `spawnSync("cat",["credentials"],{cwd})`, true},
		{"node", "-e", `spawnSync("cat",["credentials"],{cwd:""})`, false},
		{"node", "-e", `spawnSync("cat",["credentials"],{cwd:null})`, false},
		{"php", "-r", `proc_open(["cat","credentials"],[],$p,null)`, false},
		{"php", "-r", `proc_open(["cat","credentials"],[],$p,"")`, false},
		{"php", "-r", `proc_open(["cat","credentials"],[],$p,".")`, false},
		{"php", "-r", `proc_open(["cat","credentials"],[],$p,$unknown)`, true},
	} {
		if reason := AnalyzeArgv([]string{tc.program, tc.flag, tc.code}, work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.code, reason, tc.deny)
		}
	}
	code := `spawnSync("echo",["public"],{cwd:` + aws + `})`
	if reason := Analyze("node -e "+shellLiteral(code)+"; cat credentials", work, home, check); reason != "" {
		t.Errorf("child cwd escaped into the next shell statement: %s", reason)
	}
}

func TestAudit27InterpreterSourceRoles(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		argv []string
		deny bool
	}{
		{[]string{"node", "public.js", "don't"}, false},
		{[]string{"node", "public.js", `say "public`}, false},
		{[]string{"node", "--eval", `console.log("public")`, "don't"}, false},
		{[]string{"python3", "-c", "print(1)", "don't"}, false},
		{[]string{"php", "public.php", "don't"}, false},
		{[]string{"ruby", "public.rb", "don't"}, false},
		{[]string{"perl", "public.pl", "don't"}, false},
		{[]string{"lua", "public.lua", "don't"}, false},
		{[]string{"bun", "run", "public.js", "don't"}, false},
		{[]string{"deno", "run", "public.js", "don't"}, false},
		{[]string{"node", "public.js", "don't", ".env"}, true},
		{[]string{"node", "public.js", `don't read ".env"`}, true},
		{[]string{"node", "--require", "don't", "-e", `console.log("public")`}, false},
		{[]string{"node", "--eval", `console.log("public)`}, true},
		{[]string{"node", `--eval=console.log("public)`}, true},
		{[]string{"node", "-e", `console.log("public)`, "-e", `console.log("closed")`}, true},
		{[]string{"python3", "-c", `print("public)`}, true},
		{[]string{"deno", "eval", `console.log("public)`}, true},
		{[]string{"awk", `BEGIN { print "public }`}, true},
		{[]string{"awk", "BEGIN { print 1 }", "don't"}, false},
		// Unmodeled awk file sources retain their existing independent denial.
		{[]string{"awk", "-f", "public.awk", "don't"}, true},
	} {
		var quoted []string
		for _, word := range tc.argv {
			quoted = append(quoted, shellLiteral(word))
		}
		if reason := AnalyzeArgv(tc.argv, work, home, check); (reason != "") != tc.deny {
			t.Errorf("argv %q: reason=%q want deny=%v", tc.argv, reason, tc.deny)
		}
		if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != tc.deny {
			t.Errorf("shell %q: reason=%q want deny=%v", tc.argv, reason, tc.deny)
		}
	}
}

func TestAudit27UnterminatedInterpreterLiteral(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, size := range []int{8, 8192, 500000} {
		code := `console.log("` + strings.Repeat("a", size) + `)`
		tokens := interpreterTokens(code, "node")
		if len(tokens) == 0 || !tokens[len(tokens)-1].indeterminate {
			t.Errorf("unterminated literal size=%d lost indeterminate status", size)
		}
		if reason := Analyze("node <<'CODE'\n"+code+"\nCODE", work, home, check); reason == "" {
			t.Errorf("allowed unterminated literal size=%d", size)
		}
	}
	if reason := Analyze("node <<'CODE'\nconsole.log(\"public\")\nCODE", work, home, check); reason != "" {
		t.Errorf("closed public literal: %s", reason)
	}
}

// Opt in with a freshly built SECRET_AUDIT27_BINARY. Both implementations receive
// only synthetic JSON envelopes, never candidate commands as executable argv.
func TestAudit27PairedInterpreterReview(t *testing.T) {
	binary := os.Getenv("SECRET_AUDIT27_BINARY")
	if binary == "" {
		t.Skip("set SECRET_AUDIT27_BINARY to a fresh absolute Go binary for paired adapter checks")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("SECRET_AUDIT27_BINARY must be absolute")
	}
	for _, tool := range []string{"bash", "jq", "perl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("paired guard dependency %s unavailable", tool)
		}
	}
	home, work, _ := audit21Fixture(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(cwd, "..", "..", "..", "hooks", "guard-secrets")
	aws := filepath.ToSlash(filepath.Join(home, ".aws"))
	deepEval := "true"
	for i := 0; i < 8; i++ {
		deepEval = "eval " + shellLiteral(deepEval)
	}
	for _, tc := range []struct {
		name string
		argv []string
		deny bool
	}{
		{"php_upper", []string{"php", "-r", fmt.Sprintf(`PROC_OPEN(["cat","credentials"],[0=>STDIN,1=>STDOUT,2=>STDERR],$p,%q)`, aws)}, true},
		{"php_mixed", []string{"php", "-r", fmt.Sprintf(`Proc_Open(["cat","credentials"],[0=>STDIN,1=>STDOUT,2=>STDERR],$p,%q)`, aws)}, true},
		{"data_apostrophe", []string{"node", "public.js", "don't"}, false},
		{"data_protected", []string{"node", "public.js", "don't", ".env"}, true},
		{"perl_optional", []string{"perl", "-e", "print 1", "-F"}, false},
		{"luajit_optional", []string{"luajit", "-e", "print(1)", "-O"}, false},
		{"required", []string{"node", "--require"}, true},
		{"empty_source", []string{"node", "--eval", ""}, false},
		{"oversized_unclosed", []string{"node", "-e", `console.log("` + strings.Repeat("a", 9000)}, true},
		{"eval_literal", []string{"eval", "eval true"}, false},
		{"eval_wrapped", []string{"builtin", "eval", "command eval true"}, false},
		{"eval_public", []string{"eval", `eval "cat README.md"`}, false},
		{"eval_protected", []string{"eval", `eval "cat .env"`}, true},
		{"eval_dynamic", []string{"eval", `eval "$UNKNOWN"`}, true},
		{"eval_deep", []string{"bash", "-c", deepEval}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var quoted []string
			for _, word := range tc.argv {
				quoted = append(quoted, shellLiteral(word))
			}
			for _, host := range []string{"claude", "codex"} {
				for _, command := range []any{strings.Join(quoted, " "), tc.argv} {
					envelope, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "cwd": work, "tool_name": "Bash",
						"tool_input": map[string]any{"command": command},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, implementation := range []string{"bash", "go"} {
						cmd := syntheticCommand(t, "bash", guard)
						if implementation == "go" {
							cmd = syntheticCommand(t, binary, "hook", host)
						}
						cmd.Dir = work
						cmd.Stdin = bytes.NewReader(envelope)
						var stderr bytes.Buffer
						cmd.Stderr = &stderr
						output, err := cmd.Output()
						if err != nil || stderr.Len() != 0 {
							t.Errorf("%s/%s/%T: error=%v stderr=%q", implementation, host, command, err, stderr.String())
							continue
						}
						deny := false
						if len(output) != 0 {
							var decision struct {
								HookSpecificOutput struct {
									PermissionDecision string
								}
							}
							if err := json.Unmarshal(output, &decision); err != nil || decision.HookSpecificOutput.PermissionDecision != "deny" {
								t.Errorf("%s/%s/%T: invalid decision %q", implementation, host, command, output)
								continue
							}
							deny = true
						}
						if deny != tc.deny {
							t.Errorf("%s/%s/%T: deny=%v want %v", implementation, host, command, deny, tc.deny)
						}
					}
				}
			}
		})
	}
}

// S20 is a Bash precision fix: Go must keep bounded, certified literal evals
// allowed, while protected, dynamic and excessive recursion still deny.
func TestAudit27BoundedLiteralEval(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`eval 'eval true'`, false},
		{`builtin eval 'command eval true'`, false},
		{`eval 'eval "cat README.md"'`, false},
		{`eval 'eval "cat .env"'`, true},
		{`eval 'eval "$UNKNOWN"'`, true},
	} {
		if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.source, reason, tc.deny)
		}
	}
	source := "true"
	for i := 0; i < 8; i++ {
		source = "eval " + shellLiteral(source)
	}
	if reason := Analyze(source, work, home, check); reason == "" {
		t.Error("allowed eval recursion beyond the existing depth bound")
	}
}
