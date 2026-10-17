package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All source below is analyzed as data, never executed by an interpreter.
func TestAudit24ReviewLiteralWitnesses(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		program, code string
		deny          bool
	}{
		{"lua", `os.execute("dotenvx get #{x}")`, true},
		{"lua", `io.popen("dotenvx get $x")`, true},
		{"lua", `os.execute("echo hello #{x}")`, false},
		{"bun", "const x=\"\"; Bun.spawnSync([\"sh\",\"-c\",`dotenvx get ${x}`],{stdout:\"inherit\"})", true},
		{"bun", "const x=\"\"; Bun.spawnSync([\"sh\",\"-c\",`echo hello ${x}`],{stdout:\"inherit\"})", false},
		{"node", "unfamiliar(`dotenvx get ${x}`)", true},
		{"node", "unfamiliar(`ordinary public prose ${x}`)", false},
		{"python3", `unfamiliar(f"dotenvx get {x}")`, true},
		{"python3", `unfamiliar(f"ordinary public prose {x}")`, false},
		{"perl", `unfamiliar(qq{dotenvx get $x})`, true},
		{"perl", `unfamiliar(qq{ordinary public prose $x})`, false},
	} {
		flag := "-e"
		if tc.program == "python3" {
			flag = "-c"
		}
		for _, source := range []string{
			tc.program + " " + flag + " " + shellLiteral(tc.code),
			tc.program + " <<'SYNTHETIC'\n" + tc.code + "\nSYNTHETIC",
			tc.program + " <<< " + shellLiteral(tc.code),
			"printf '%s\\n' " + shellLiteral(tc.code) + " | " + tc.program,
		} {
			if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
			}
		}
		if reason := AnalyzeArgv([]string{tc.program, flag, tc.code}, work, home, check); (reason != "") != tc.deny {
			t.Errorf("argv %s %s: reason=%q want deny=%v", tc.program, tc.code, reason, tc.deny)
		}
	}
}

func TestAudit24ReviewStaticStrings(t *testing.T) {
	for _, tc := range []struct {
		program, code string
		literal       bool
	}{
		{"lua", `"dotenvx get #{x}"`, true},
		{"lua", `"dotenvx get $x"`, true},
		{"node", `"echo $x #{x}"`, true},
		{"rscript", `"echo $x #{x}"`, true},
		{"ruby", `"echo #{x}"`, false},
		{"perl", `"echo $x"`, false},
		{"php", `"echo $x"`, false},
		{"bun", "`echo ${x}`", false},
		{"python3", `f"echo {x}"`, false},
		{"perl", `qq{echo $x}`, false},
	} {
		tokens := interpreterTokens(tc.code, tc.program)
		if len(tokens) != 1 || tokens[0].literal != tc.literal || !tokens[0].witness {
			t.Errorf("%s %s: %#v", tc.program, tc.code, tokens)
		}
		if _, _, known := literalArguments(append(tokens, interpreterToken{text: ")"}), 0, ")"); known != tc.literal {
			t.Errorf("%s %s: static argv=%v want=%v", tc.program, tc.code, known, tc.literal)
		}
	}
}

func TestAudit24ReviewConfiguredHOME(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(home, "kc.yaml"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, prefix := range []string{"", "declare ", "export -n ", "export ", "readonly ", "command export -n "} {
			for _, value := range []string{`"$HOME/kc.yaml"`, `$HOME/kc.yaml`, `"${HOME}/kc.yaml"`, `${HOME}/kc.yaml`} {
				for _, file := range []string{"~/kc.yaml", "README.md"} {
					source := prefix + key + "=" + value + "; cat " + file
					if reason := Analyze(source, work, home, check); (reason != "") != (file == "~/kc.yaml") {
						t.Errorf("%s: reason=%q", source, reason)
					}
				}
			}
			for _, value := range []string{`"$unknown/kc.yaml"`, `"$(echo public)/kc.yaml"`} {
				if source := prefix + key + "=" + value + "; cat ~/kc.yaml"; Analyze(source, work, home, check) == "" {
					t.Errorf("unresolved configured assignment allowed: %s", source)
				}
			}
		}
	}
}

func TestAudit24ReviewRecursiveEmptyTree(t *testing.T) {
	home, _, check := audit21Fixture(t)
	work := t.TempDir() // No protected file exists to invalidate a tree proof.
	for _, child := range []struct {
		text string
		deny bool
	}{
		{"grep -r TOKEN .", true}, {"grep -R TOKEN .", true},
		{"grep --recursive TOKEN .", true},
		{"grep -rl TOKEN .", false}, {"grep -rc TOKEN .", false},
		{"grep TOKEN public.txt", false}, {"echo hello", false},
	} {
		for _, preceding := range []string{"", `os.execute("tar xf public.tar"); `} {
			code := preceding + fmt.Sprintf("os.execute(%q)", child.text)
			for _, source := range []string{
				"lua -e " + shellLiteral(code),
				"lua <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
				"lua <<< " + shellLiteral(code),
				"printf '%s\\n' " + shellLiteral(code) + " | lua",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
				}
			}
		}
	}
	if reason := Analyze("grep -r TOKEN .", work, home, check); reason != "" {
		t.Errorf("direct empty-tree proof changed: %s", reason)
	}
}

func TestAudit24ReviewBunInlineCWD(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, option := range []string{"--cwd %s", "--cwd=%s"} {
		for _, action := range []string{"-e", "run -e"} {
			for _, file := range []string{"credentials", "public.txt"} {
				code := fmt.Sprintf(`console.log(require("fs").readFileSync(%q,"utf8"))`, file)
				directory := filepath.ToSlash(filepath.Join(home, ".aws"))
				args := []string{"bun", "--cwd", directory}
				if strings.Contains(option, "=") {
					args = []string{"bun", "--cwd=" + directory}
				}
				args = append(args, strings.Fields(action)...)
				args = append(args, code)
				source := "bun " + fmt.Sprintf(option, shellLiteral(filepath.ToSlash(filepath.Join(home, ".aws")))) + " " + action + " " + shellLiteral(code)
				runtime := "bun " + fmt.Sprintf(option, shellLiteral(directory))
				for shape, reason := range map[string]string{
					"shell":       Analyze(source, work, home, check),
					"argv":        AnalyzeArgv(args, work, home, check),
					"heredoc":     Analyze(runtime+" <<'SYNTHETIC'\n"+code+"\nSYNTHETIC", work, home, check),
					"here-string": Analyze(runtime+" <<< "+shellLiteral(code), work, home, check),
					"pipe":        Analyze("printf '%s\\n' "+shellLiteral(code)+" | "+runtime, work, home, check),
				} {
					if (reason != "") != (file == "credentials") {
						t.Errorf("%s %s: reason=%q", shape, source, reason)
					}
				}
			}
		}
	}
	if reason := Analyze(`bun --cwd ~/.aws -e 'console.log("hello")'; cat credentials`, work, home, check); reason != "" {
		t.Errorf("Bun runtime cwd escaped invocation: %s", reason)
	}
}
