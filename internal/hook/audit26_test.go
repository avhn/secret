package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Candidate commands are JSON data only. Both adapters use a fake HOME and
// disposable metadata; no candidate interpreter, printer or reader is launched.
func audit26EnvelopeCheck(t *testing.T) func(*testing.T, any, bool) {
	t.Helper()
	requireBashAnalysis(t)
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "README.md"), []byte("public\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "RIPGREP_CONFIG_PATH"} {
		t.Setenv(key, "")
	}
	return func(t *testing.T, command any, deny bool) {
		t.Helper()
		for _, host := range []string{"claude", "codex"} {
			body, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": work, "tool_input": map[string]any{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			if err := Decide(host, bytes.NewReader(body), &output); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(output.String(), `"permissionDecision":"deny"`); got != deny {
				t.Errorf("%s command=%q deny=%v want=%v: %s", host, command, got, deny, output.String())
			}
		}
	}
}

func audit26Shell(words []string) string {
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = "'" + strings.ReplaceAll(word, "'", "'\\''") + "'"
	}
	return strings.Join(quoted, " ")
}

func TestAudit26MemberEnvelopes(t *testing.T) {
	check := audit26EnvelopeCheck(t)
	for _, tc := range []struct {
		name, option, code string
	}{
		{"python3", "-c", `import subprocess; subprocess%srun(["gh","auth","token"])`},
		{"pypy3", "-c", `import subprocess; subprocess%srun(["gh","auth","token"])`},
		{"node", "-e", `require("child_process")%sspawnSync("gh",["auth","token"])`},
		{"nodejs", "-e", `require("child_process")%sexecFileSync("gh",["auth","token"])`},
		{"bun", "-e", `Bun%sspawnSync(["gh","auth","token"])`},
		{"deno", "eval", `new Deno%sCommand("gh",{args:["auth","token"]}).outputSync()`},
		{"ruby", "-e", `Kernel%ssystem("gh","auth","token")`},
		{"lua5.4", "-e", `os%sexecute("gh auth token")`},
		{"luajit", "-e", `os%sexecute("gh auth token")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for index, member := range []string{".", ". ", ".\n", ".\t\n  ", " . ", "\n.\n"} {
				for _, deny := range []bool{true, false} {
					t.Run(fmt.Sprintf("member%d/deny%v", index, deny), func(t *testing.T) {
						code := fmt.Sprintf(tc.code, member)
						if !deny {
							code = strings.ReplaceAll(code, "gh", "echo")
						}
						words := []string{tc.name, tc.option, code}
						check(t, words, deny)
						check(t, audit26Shell(words), deny)
						check(t, tc.name+" <<'SYNTHETIC'\n"+code+"\nSYNTHETIC", deny)
						check(t, tc.name+" <<< "+audit26Shell([]string{code}), deny)
						check(t, "printf '%s\\n' "+audit26Shell([]string{code})+" | "+tc.name, deny)
					})
				}
			}
		})
	}
	for _, code := range []string{
		`console.log('new Deno. Command("gh",{args:["auth","token"]})')`,
		"// new Deno. Command(\"gh\",{args:[\"auth\",\"token\"]})\nconsole.log('public')",
		`/* new Deno. Command("gh",{args:["auth","token"]}) */ console.log('public')`,
		`const data = /Deno. Command("gh",args:["auth","token"])/; console.log('public')`,
	} {
		check(t, []string{"deno", "eval", code}, false)
		check(t, audit26Shell([]string{"deno", "eval", code}), false)
	}
}

func TestAudit26AttachedCodeEnvelopes(t *testing.T) {
	check := audit26EnvelopeCheck(t)
	for _, tc := range []struct {
		name    string
		options []string
		code    string
	}{
		{"ruby", []string{"-e", "-we", "-ne", "-pe", "-W0e", "-Se", "-0e", "-0777e", "-0777ne"}, `system("aws","ecr","get-login-password");`},
		{"perl", []string{"-e", "-E", "-we", "-ne", "-pe", "-0777ne", "-fWe"}, `exec("aws","ecr","get-login-password");`},
		{"ruby", []string{"-e", "-we"}, `exec("gh","auth","token");`},
		{"perl", []string{"-e", "-E"}, `system("gh","auth","token");`},
		{"python", []string{"-c", "-Ic", "-Bbc"}, `import subprocess; subprocess. run(["aws","ecr","get-login-password"])`},
		{"python3.12", []string{"-c"}, `import subprocess; subprocess.run(["aws","ecr","get-login-password"])`},
		{"pypy", []string{"-c"}, `import subprocess; subprocess.run(["aws","ecr","get-login-password"])`},
		{"pypy3", []string{"-c"}, `import subprocess; subprocess.run(["aws","ecr","get-login-password"])`},
		{"node", []string{"-e", "-p", "-pe", "-ipe", "--eval=", "--print="}, `execFileSync("aws",["ecr","get-login-password"])`},
		{"nodejs", []string{"-e", "-p", "--eval="}, `execFileSync("aws",["ecr","get-login-password"])`},
		{"bun", []string{"-e", "-p", "--eval=", "--print="}, `Bun. spawnSync(["aws","ecr","get-login-password"])`},
		{"deno", []string{"--eval=", "--print="}, `new Deno. Command("aws",{args:["ecr","get-login-password"]}).outputSync()`},
		{"lua", []string{"-e"}, `os.execute("aws ecr get-login-password")`},
		{"lua5.4", []string{"-e"}, `os.execute("aws ecr get-login-password")`},
		{"luajit", []string{"-e"}, `os.execute("aws ecr get-login-password")`},
		{"php", []string{"-r", "-nr", "-B", "-R", "-E", "--run=", "--process-begin=", "--process-code=", "--process-end="}, `proc_open(["aws","ecr","get-login-password"],[], $pipes);`},
		{"Rscript", []string{"-e"}, `system("aws ecr get-login-password")`},
		{"awk", []string{"-e", "--source="}, `BEGIN { system("aws ecr get-login-password") }`},
		{"gawk", []string{"-e", "--source="}, `BEGIN { system("aws ecr get-login-password") }`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, option := range tc.options {
				for _, deny := range []bool{true, false} {
					code := tc.code
					if !deny {
						code = strings.ReplaceAll(strings.ReplaceAll(code, "aws", "echo"), "gh", "echo")
					}
					for _, attached := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/deny%v/attached%v", option, deny, attached), func(t *testing.T) {
							words := []string{tc.name, strings.TrimSuffix(option, "="), code}
							if attached {
								words = []string{tc.name, option + code}
							}
							for _, prefix := range [][]string{nil, {"env", "SYNTHETIC=public"}} {
								argv := append(append([]string(nil), prefix...), words...)
								check(t, argv, deny)
								check(t, audit26Shell(argv), deny)
							}
						})
					}
				}
			}
		})
	}
	for _, encoding := range [][]string{{"-E", "UTF-8"}, {"-EUTF-8"}, {"-wE", "UTF-8"}} {
		for _, code := range []string{`system("aws","ecr","get-login-password");`, `system("echo","public");`, `puts("public")`} {
			for _, attached := range []bool{false, true} {
				words := append([]string{"ruby"}, encoding...)
				if attached {
					words = append(words, "-e"+code)
				} else {
					words = append(words, "-e", code)
				}
				for _, prefix := range [][]string{nil, {"env", "SYNTHETIC=public"}} {
					argv := append(append([]string(nil), prefix...), words...)
					deny := strings.Contains(code, "aws")
					check(t, argv, deny)
					check(t, audit26Shell(argv), deny)
				}
			}
		}
	}
	for _, argv := range [][]string{
		{"ruby", "-0eputs('public')"}, {"ruby", "-0777eputs('public')"},
		{"ruby", "-eputs('public')"}, {"perl", "-Eprint('public')"},
		{"python3", "-cprint('public')"}, {"node", "--eval=console.log('public')"},
		{"node", "--env-file=README.md", "-econsole.log('public')"},
		{"ruby", `-esystem("cat","README.md")`},
		{"ruby", "README.md", `-esystem("aws","ecr","get-login-password")`},
		{"node", "README.md", `-eexecFileSync("aws",["ecr","get-login-password"])`},
		{"ruby", `-eputs('system("aws","ecr","get-login-password")')`},
		{"perl", `-eprint('exec("aws","ecr","get-login-password")')`},
		{"python3", `-cprint('subprocess.run(["aws","ecr","get-login-password"])')`},
		{"node", `-econsole.log('execFileSync("aws",["ecr","get-login-password"])')`},
		{"perl", `-Eexec("cat","README.md")`},
		{"python3", `-cimport subprocess; subprocess.run(["cat","README.md"])`},
		{"node", `--eval=execFileSync("cat",["README.md"])`},
		{"bun", `-eBun.spawnSync(["cat","README.md"])`},
		{"deno", `--eval=new Deno. Command("cat",{args:["README.md"]}).outputSync()`},
		{"lua", `-eos.execute("cat README.md")`},
		{"php", `-rproc_open(["cat","README.md"],[], $pipes);`},
		{"Rscript", `-esystem("cat README.md")`},
		{"jq", "--arg", "public", "-esystem", "."}, {"yq", ".public"},
	} {
		check(t, argv, false)
		check(t, audit26Shell(argv), false)
	}
}
