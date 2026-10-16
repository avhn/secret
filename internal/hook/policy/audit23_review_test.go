package policy

import (
	"fmt"
	"testing"
)

func TestAudit23ReviewPythonShellLaunches(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, program := range []string{"python3", "pypy3"} {
		for _, api := range []string{"system", "popen"} {
			for _, prefix := range []string{"", "r", "b", "f", "rb", "br", "rf", "fr", "u", "R", "B", "F", "Rb", "fR"} {
				for _, child := range []struct {
					source string
					deny   bool
				}{{"dotenvx get", true}, {"npm run env", true}, {"git status", false}} {
					code := fmt.Sprintf("import os; os.%s(%s%q)", api, prefix, child.source)
					for _, source := range []string{
						program + " -c " + shellLiteral(code),
						program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
					} {
						if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
							t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
						}
					}
					if reason := AnalyzeArgv([]string{program, "-c", code}, work, home, check); (reason != "") != child.deny {
						t.Errorf("argv %s: reason=%q want deny=%v", code, reason, child.deny)
					}
				}
			}
		}
		for _, code := range []string{
			`exec("print(1)")`,
			`exec("import math; print(math.pi)")`,
			`exec(r"print(1)")`,
			`exec(b"print(1)")`,
			`exec(f"print(1)")`,
		} {
			if reason := Analyze(program+" -c "+shellLiteral(code), work, home, check); reason != "" {
				t.Errorf("Python source is not shell source %s %s: %s", program, code, reason)
			}
		}
		if reason := Analyze(program+" -c "+shellLiteral(`exec("open('.env').read()")`), work, home, check); reason == "" {
			t.Errorf("Python exec lost protected-source checks: %s", program)
		}
	}
}

func TestAudit23ReviewPythonEscapedShellLaunches(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, literal := range []struct {
		source string
		deny   bool
	}{
		{`b"dotenvx\x20get"`, true},
		{`u"` + `\` + `u0064otenvx\040get"`, true},
		{`f"\x64otenvx get"`, true},
		{`r"dotenvx\ get"`, false},
		{`b"git\x20status"`, false},
		{`u"` + `\` + `u0067it\040status"`, false},
		{`rf"printf '{{public}}'"`, false},
	} {
		for _, api := range []string{"system", "popen"} {
			code := "import os; os." + api + "(" + literal.source + ")"
			if reason := Analyze("python3 -c "+shellLiteral(code), work, home, check); (reason != "") != literal.deny {
				t.Errorf("%s: reason=%q want deny=%v", code, reason, literal.deny)
			}
		}
	}
}

func TestAudit23ReviewPythonLiteralTokens(t *testing.T) {
	for _, tc := range []struct {
		source string
		value  string
		known  bool
	}{
		{`r"git\tstatus"`, `git\tstatus`, true},
		{`"git\tstatus"`, "git\tstatus", true},
		{`r'git\'status'`, `git\'status`, true},
		{`rb"git\x20status"`, `git\x20status`, true},
		{`b"git\x20status"`, "git status", true},
		{`b"git` + `\` + `u0020status"`, `git` + `\` + `u0020status`, true},
		{`b"\xff\400"`, string([]byte{255, 0}), true},
		{`u"` + `\` + `u0067it\040status"`, "git status", true},
		{`"\U0001f600"`, "\U0001f600", true},
		{`'git\"status'`, `git"status`, true},
		{`"git\'status"`, "git'status", true},
		{`"git\ status"`, `git\ status`, true},
		{"b\"git\\\n status\"", "git status", true},
		{"\"git\\\r\n status\"", "git status", true},
		{`f"git {{public}}"`, "git {public}", true},
		{`rf"git \{{public}}"`, `git \{public}`, true},
		{`f"git {value}"`, "git {value}", false},
		{`rf"git \{value\}"`, `git \{value\}`, false},
		{`f"git \{value\}"`, `git \{value\}`, false},
		{`f"git }"`, "git }", false},
		{`b"non-ascii ` + `\` + `u00e9"`, `non-ascii ` + `\` + `u00e9`, true},
		{`b"non-ascii é"`, "non-ascii é", false},
		{`"\N{SPACE}"`, `\N{SPACE}`, false},
		{`r"""public " text"""`, `public " text`, true},
		{`fr'''public ' {{text}}'''`, "public ' {text}", true},
	} {
		t.Run(tc.source, func(t *testing.T) {
			tokens := interpreterTokens(tc.source+"; marker", "python3")
			if len(tokens) != 3 || tokens[0].text != tc.value || tokens[0].literal != tc.known || tokens[1].text != ";" || tokens[2].text != "marker" {
				t.Errorf("tokens=%#v want value=%q literal=%v followed by marker", tokens, tc.value, tc.known)
			}
		})
	}
	for _, source := range []string{`bf"public"`, `rr"public"`, `name"public"`} {
		tokens := interpreterTokens(source, "python3")
		for _, token := range tokens {
			if token.literal {
				t.Errorf("unsupported prefix supplied a literal: %s %#v", source, tokens)
			}
		}
	}
}
