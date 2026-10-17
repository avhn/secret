package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

// These commands are policy input only, never interpreter or child execution.
func TestAudit24InterpreterLiterals(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, runtime := range []struct{ name, inline string }{
		{"python3", "-c"}, {"pypy3", "-c"}, {"node", "-e"}, {"nodejs", "-e"},
		{"bun", "-e"}, {"bun", "--eval"}, {"bun", "-p"}, {"bun", "run -e"},
		{"deno", "eval"}, {"ruby", "-e"}, {"perl", "-e"}, {"php", "-r"},
		{"lua", "-e"}, {"luajit", "-e"}, {"lua5.4", "-e"}, {"Rscript", "-e"},
	} {
		for _, literal := range []struct {
			text string
			deny bool
		}{
			{"dotenvx get", true}, {"dotenvx decrypt --stdout", true},
			{"npm run env", true}, {"npm exec -- env", true},
			{"python3 -m keyring get synthetic synthetic", true},
			{"secret get synthetic", true}, {"grep -r TOKEN .", true},
			{"gh auth token", true}, {"cat .env", true},
			{"ordinary public prose", false}, {"echo hello", false},
			{"cat README.md", false}, {"aws sts get-caller-identity", false},
		} {
			// An unfamiliar API must not evade the broad literal fallback.
			code := fmt.Sprintf("unfamiliar(%q)", literal.text)
			for _, source := range []string{
				runtime.name + " " + runtime.inline + " " + shellLiteral(code),
				runtime.name + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
				"printf '%s\\n' " + shellLiteral(code) + " | " + runtime.name,
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != literal.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, literal.deny)
				}
			}
			argv := append([]string{runtime.name}, strings.Fields(runtime.inline)...)
			if reason := AnalyzeArgv(append(argv, code), work, home, check); (reason != "") != literal.deny {
				t.Errorf("argv %s %s: reason=%q want deny=%v", runtime.name, code, reason, literal.deny)
			}
		}
	}
}

func TestAudit24InterpreterLaunches(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, api := range []struct{ program, flag, call string }{
		{"python3", "-c", "import pty; pty.spawn([%s])"},
		{"bun", "-e", "Bun.spawn([%s])"},
		{"bun", "-e", "Bun.spawnSync([%s], {stdout:'inherit'})"},
		{"ruby", "-e", "spawn(%s); Process.wait"},
		{"ruby", "-e", "Process.spawn(%s)"},
		{"ruby", "-e", "Kernel.spawn(%s)"},
		{"ruby", "-e", "spawn %s"},
		{"ruby", "-e", "puts IO.popen([%s]).read"},
		{"node", "-e", "require('child_process').spawnSync(%s,{stdio:'inherit'})"},
		{"deno", "eval", "import {spawnSync} from 'node:child_process'; spawnSync(%s)"},
	} {
		for _, child := range []struct {
			words []string
			deny  bool
		}{
			{[]string{"gh", "auth", "token"}, true},
			{[]string{"aws", "ecr", "get-login-password"}, true},
			{[]string{"git", "status"}, false},
		} {
			var words []string
			for _, word := range child.words {
				words = append(words, fmt.Sprintf("%q", word))
			}
			args := strings.Join(words, ",")
			if api.program == "node" || api.program == "deno" {
				args = "`" + child.words[0] + "`,["
				for i, word := range child.words[1:] {
					if i > 0 {
						args += ","
					}
					args += "`" + word + "`"
				}
				args += "]"
			}
			code := fmt.Sprintf(api.call, args)
			for _, source := range []string{
				api.program + " " + api.flag + " " + shellLiteral(code),
				api.program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
				api.program + " <<< " + shellLiteral(code),
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
				}
			}
			if reason := AnalyzeArgv([]string{api.program, api.flag, code}, work, home, check); (reason != "") != child.deny {
				t.Errorf("argv %s: reason=%q want deny=%v", code, reason, child.deny)
			}
		}
	}
}

func TestAudit24ShellLiteralAPIs(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, api := range []struct{ program, flag, call string }{
		{"lua", "-e", "os.execute(%q)"}, {"lua5.4", "-e", "io.popen(%q)"},
		{"php", "-r", "shell_exec(%q);"}, {"php", "-r", "passthru(%q);"},
		{"php", "-r", "popen(%q, 'r');"}, {"php", "-r", "proc_open(%q, [], $pipes);"},
		{"php", "-r", "system(%q, $rc);"}, {"php", "-r", "exec(%q, $out, $rc);"},
		{"Rscript", "-e", "system(%q, intern=TRUE)"}, {"Rscript", "-e", "system(command=%q)"},
		{"Rscript", "-e", "pipe(%q)"}, {"ruby", "-e", "IO.popen(%q)"},
		{"ruby", "-e", "Open3.capture2(%q)"}, {"ruby", "-e", "Open3.capture3(%q)"},
		{"ruby", "-e", "Open3.popen3(%q)"}, {"perl", "-e", "open(my $f, %q . ' |');"},
		{"node", "-e", "require('child_process').execSync(`%s`, {stdio:'inherit'})"},
	} {
		for _, child := range []struct {
			source string
			deny   bool
		}{{"dotenvx get", true}, {"python3 -m keyring get s u", true}, {"echo hello", false}, {"cat README.md", false}} {
			code := fmt.Sprintf(api.call, child.source)
			for _, source := range []string{
				api.program + " " + api.flag + " " + shellLiteral(code),
				api.program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
				}
			}
		}
	}
}

func TestAudit24PerlQuotes(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, pair := range []string{"{}", "()", "[]", "<>", "!!", "//", "##"} {
		for _, kind := range []string{"q", "qq", "qx"} {
			for _, child := range []struct {
				text string
				deny bool
			}{{"env", true}, {"npm run env", true}, {"grep -r TOKEN .", true}, {"echo hello", false}, {"cat README.md", false}} {
				quoted := kind + pair[:1] + child.text + pair[1:]
				code := "system(" + quoted + ");"
				if kind == "qx" {
					code = "print " + quoted + ";"
				}
				for _, source := range []string{"perl -e " + shellLiteral(code), "perl <<'SYNTHETIC'\n" + code + "\nSYNTHETIC"} {
					if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
					}
				}
			}
		}
	}
	for _, tc := range []struct {
		code string
		deny bool
	}{{"system(qw(gh auth token));", true}, {"system(qw(git status));", false}, {"print q{public {nested} prose};", false}} {
		if reason := Analyze("perl -e "+shellLiteral(tc.code), work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.code, reason, tc.deny)
		}
	}
}

func TestAudit24BunCWD(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, option := range []string{"--cwd %s", "--cwd=%s"} {
		for _, action := range []string{"", "x ", "run ", "exec "} {
			for _, child := range []struct {
				command string
				deny    bool
			}{{"cat credentials", true}, {"cat public.txt", false}, {"stat credentials", false}, {"node -e \"require('fs').readFileSync('credentials')\"", true}} {
				source := "bun " + fmt.Sprintf(option, shellLiteral(filepath.ToSlash(filepath.Join(home, ".aws")))) + " " + action + child.command
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
				}
			}
		}
	}
	if reason := Analyze("bun --cwd ~/.aws run echo hello; cat credentials", work, home, check); reason != "" {
		t.Errorf("Bun cwd escaped the child: %s", reason)
	}
}

func TestAudit24ConfiguredDeclarations(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, declaration := range []string{"export", "readonly", "declare", "declare -x", "typeset -x"} {
			for _, assignment := range []string{key + "=kc.yaml", "if true; then " + key + "=kc.yaml; fi", "if true; then " + key + "=kc.yaml; else " + key + "=other.yaml; fi"} {
				for _, file := range []string{"kc.yaml", "README.md"} {
					source := assignment + "; " + declaration + " " + key + "; cat " + file
					if reason := Analyze(source, work, home, check); (reason != "") != (file == "kc.yaml" || strings.HasSuffix(declaration, " -x")) {
						t.Errorf("%s: reason=%q", source, reason)
					}
				}
			}
		}
		for _, prefix := range []string{"", "export ", "readonly ", "declare "} {
			for _, reader := range []string{"cat ~/kc.yaml", "python3 -c \"open('" + filepath.ToSlash(home) + "/kc.yaml').read()\""} {
				source := prefix + key + "=~/kc.yaml; " + reader
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("tilde assignment allowed: %s", source)
				}
			}
		}
		if reason := Analyze(key+"=kc.yaml; export "+key+"=other.yaml; cat kc.yaml", work, home, check); reason != "" {
			t.Errorf("sequential replacement lost precision: %s", reason)
		}
	}
}

func TestAudit24LiteralTokenBoundaries(t *testing.T) {
	for _, program := range []string{"node", "nodejs", "bun", "deno"} {
		for _, tc := range []struct {
			code  string
			known bool
		}{
			{"`gh auth token`", true},
			{"`echo ${value}`", false},
			{"`echo public\ntext`", true},
		} {
			tokens := interpreterTokens(tc.code, program)
			if len(tokens) != 1 || tokens[0].literal != tc.known || tokens[0].shell {
				t.Errorf("%s %s: %#v", program, tc.code, tokens)
			}
		}
		for _, code := range []string{"// unfamiliar(\"dotenvx get\")", "/* unfamiliar(\"dotenvx get\") */", "const re = /unfamiliar(\"dotenvx get\")/;"} {
			for _, token := range interpreterTokens(code, program) {
				if token.literal {
					t.Errorf("%s comment/regex supplied a literal: %s %#v", program, code, token)
				}
			}
		}
	}
	for _, tc := range []struct {
		code, value  string
		known, shell bool
	}{
		{`q{public {nested} prose}`, "public {nested} prose", true, false},
		{`q!public \! text!`, "public ! text", true, false},
		{`q{public \} text}`, "public } text", true, false},
		{`qq{echo $value}`, "echo $value", false, false},
		{`qx(echo public)`, "echo public", true, true},
		{`q{unterminated`, "unterminated", false, false},
	} {
		tokens := interpreterTokens(tc.code, "perl")
		if len(tokens) != 1 || tokens[0].text != tc.value || tokens[0].literal != tc.known || tokens[0].shell != tc.shell {
			t.Errorf("%s: %#v", tc.code, tokens)
		}
	}
}

func TestAudit24InterpreterScanLimits(t *testing.T) {
	home, work, check := audit21Fixture(t)
	// The argv adapter reaches the exact decoded-literal boundary without the
	// existing shell-word byte limit also counting its enclosing shell quotes.
	if reason := AnalyzeArgv([]string{"python3", "-c", `unfamiliar("` + strings.Repeat("a", 8192) + `")`}, work, home, check); reason != "" {
		t.Errorf("exact decoded-literal byte boundary: %s", reason)
	}
	if reason := Analyze("python3 <<'SYNTHETIC'\n"+strings.Repeat("a", 11000)+"\nSYNTHETIC", work, home, check); reason != "" {
		t.Errorf("large inert heredoc is not a literal record: %s", reason)
	}
	for _, tc := range []struct {
		name, code string
		deny       bool
	}{
		{"literal bytes adapter control", `unfamiliar("` + strings.Repeat("a", 8000) + `")`, false},
		{"literal bytes exceeded", `unfamiliar("` + strings.Repeat("a", 8193) + `")`, true},
		{"literals boundary", strings.Repeat("x='a'\n", 256), false},
		{"literals exceeded", strings.Repeat("x='a'\n", 257), true},
		{"mixed literals boundary", strings.Repeat("print('a', 1)\n", 128), false},
		{"mixed literals exceeded", strings.Repeat("print('a', 1)\n", 129), true},
		{"fanout boundary", strings.Repeat("x=1;", 128) + "print('a')", false},
		{"fanout exceeded", strings.Repeat("x=1;", 129) + "print('a')", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for shape, reason := range map[string]string{
				"inline":      Analyze("python3 -c "+shellLiteral(tc.code), work, home, check),
				"heredoc":     Analyze("python3 <<'SYNTHETIC'\n"+tc.code+"\nSYNTHETIC", work, home, check),
				"here-string": Analyze("python3 <<< "+shellLiteral(tc.code), work, home, check),
				"pipe":        Analyze("printf '%s' "+shellLiteral(tc.code)+" | python3", work, home, check),
				"argv":        AnalyzeArgv([]string{"python3", "-c", tc.code}, work, home, check),
			} {
				if (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", shape, reason, tc.deny)
				}
			}
		})
	}
}

func TestAudit24ScalarQuoteRemoval(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source, value string
		known         bool
	}{
		{shellLiteral("x='a'\n"), "x='a'\n", true},
		{`public\ words`, "public words", true},
		{`\~`, "~", true},
		{`'~'`, "~", true},
		{`~/public`, home + "/public", true},
		{`'${HOME}'`, "${HOME}", true},
		{`\$HOME`, "$HOME", true},
		{`"$HOME/public"`, home + "/public", true},
		{`"public\\words"`, `public\words`, true},
		{"public\\\nwords", "publicwords", true},
		{`"$unknown"`, "", false},
		{`$(echo public)`, "", false},
	} {
		source := "python3 <<< " + tc.source
		file, err := syntax.NewParser().Parse(strings.NewReader(source), "")
		if err != nil {
			t.Fatal(err)
		}
		a := analyzer{protected: check, source: source, cwd: work, home: home, deadline: time.Now().Add(time.Second)}
		value, known := a.expandInterpreterStdin(file.Stmts[0].Redirs[0].Word, false, work)
		if known != tc.known || known && value != tc.value {
			t.Errorf("%s: value=%q known=%v want value=%q known=%v", tc.source, value, known, tc.value, tc.known)
		}
	}
}

func TestAudit24PerlWordListScanLimits(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, count := range []int{256, 257} {
		code := "unfamiliar(qw(" + strings.Repeat("a ", count) + "))"
		for shape, reason := range map[string]string{
			"inline":  Analyze("perl -e "+shellLiteral(code), work, home, check),
			"stdin":   Analyze("perl <<< "+shellLiteral(code), work, home, check),
			"argv":    AnalyzeArgv([]string{"perl", "-e", code}, work, home, check),
			"heredoc": Analyze("perl <<'SYNTHETIC'\n"+code+"\nSYNTHETIC", work, home, check),
		} {
			if (reason != "") != (count > 256) {
				t.Errorf("%s %d words: reason=%q", shape, count, reason)
			}
		}
	}
}
