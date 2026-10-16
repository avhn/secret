package policy

import (
	"fmt"
	"strings"
	"testing"
)

func TestAudit23PythonTripleQuotes(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, quote := range []string{`"""`, `'''`} {
		for _, body := range []string{"public " + quote[:1] + " text", "public\n" + quote[:1] + " text", "escaped \\" + quote[:1] + " text"} {
			for _, launch := range []struct {
				code string
				deny bool
			}{
				{`subprocess.run(['aws','ecr','get-login-password'])`, true},
				{`subprocess.run(['op','item','get','synthetic','--otp'])`, true},
				{`subprocess.run(['git','status'])`, false},
			} {
				code := quote + body + quote + "\nimport subprocess\n" + launch.code
				for _, source := range []string{
					"python3 -c " + shellLiteral(code),
					"python3 <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
					"printf '%s\\n' " + shellLiteral(code) + " | python3",
				} {
					if reason := Analyze(source, work, home, check); (reason != "") != launch.deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, launch.deny)
					}
				}
				if reason := AnalyzeArgv([]string{"python3", "-c", code}, work, home, check); (reason != "") != launch.deny {
					t.Errorf("argv %s: reason=%q want deny=%v", code, reason, launch.deny)
				}
			}
		}
		code := quote + "subprocess.run(['aws','ecr','get-login-password'])" + quote + "\nprint('public')"
		tokens := interpreterTokens(code, "python3")
		if len(tokens) != 5 || !tokens[0].literal || tokens[1].text != "print" {
			t.Errorf("triple-quoted data is not opaque: %#v", tokens)
		}
		if reason := Analyze("python3 -c "+shellLiteral(code), work, home, check); reason != "" {
			t.Errorf("triple-quoted data: %s", reason)
		}
	}
}

func TestAudit23GitHubAPIFields(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, prefix := range []string{"", "--hostname public ", "--hostname=public ", "-R public/project ", "--hostname api "} {
		for _, field := range []string{"-F data=@%s", "-Fdata=@%s", "-f data=@%s", "-fdata=@%s", "--field data=@%s", "--field=data=@%s", "--raw-field data=@%s", "--raw-field=data=@%s"} {
			for _, file := range []string{".env", "README.md"} {
				source := "gh " + prefix + "api /synthetic " + fmt.Sprintf(field, file)
				for _, reason := range []string{Analyze(source, work, home, check), AnalyzeArgv(strings.Fields(source), work, home, check)} {
					if (reason != "") != (file == ".env") {
						t.Errorf("%s: reason=%q", source, reason)
					}
				}
			}
		}
	}
	for _, source := range []string{"gh --hostname api issue list", "gh issue create --title api --body public", "gh --hostname public api /synthetic --field data=public"} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("non-file API data %s: %s", source, reason)
		}
	}
}

func TestAudit23CurlDecodedControls(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, escape := range []string{"%00", "%09", "%0A", "%0D", "%1F", "%7F", "%20", "%2509"} {
		for _, scheme := range []string{"file:", "file://", "file://localhost"} {
			for _, option := range []string{"", "--url ", "--url="} {
				source := "curl " + option + scheme + "/synthetic/public" + escape + "name"
				deny := escape != "%20" && escape != "%2509"
				for _, reason := range []string{Analyze(source, work, home, check), AnalyzeArgv(strings.Fields(source), work, home, check)} {
					if (reason != "") != deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, deny)
					}
				}
			}
		}
	}
	for _, source := range []string{"curl --url https://synthetic.invalid/public%09name", "curl --data file:/synthetic/public%09name https://synthetic.invalid"} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("non-file URL %s: %s", source, reason)
		}
	}
}

func TestAudit23InterpreterShellDispatch(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, api := range []struct{ program, flag, call string }{
		{"python3", "-c", "import os; os.system(%s)"},
		{"python3", "-c", "import subprocess; subprocess.run(%s, shell=True)"},
		{"node", "-e", "require('child_process').execSync(%s)"},
		{"node", "-e", "require('child_process').exec(%s)"},
		{"ruby", "-e", "system(%s)"},
		{"ruby", "-e", "exec(%s)"},
		{"perl", "-e", "system(%s)"},
		{"ruby", "-e", "system %s"},
		{"perl", "-e", "exec %s;"},
	} {
		for _, child := range []struct {
			source string
			deny   bool
		}{
			{"dotenvx get", true}, {"dotenvx decrypt --stdout", true},
			{"npm run env", true}, {"npm exec -- env", true},
			{"python3 -m keyring get synthetic synthetic", true},
			{"cat .env", true}, {"cd ~/.aws; cat credentials", true},
			{"git status", false}, {"cat README.md", false},
			{"printf public", false},
		} {
			code := fmt.Sprintf(api.call, `"`+child.source+`"`)
			for _, source := range []string{
				api.program + " " + api.flag + " " + shellLiteral(code),
				api.program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
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
	for _, code := range []string{`print("dotenvx get")`, `print("npm run env")`, `print("npm exec -- env")`, `print("python3 -m keyring get synthetic synthetic")`} {
		if reason := Analyze("python3 -c "+shellLiteral(code), work, home, check); reason != "" {
			t.Errorf("ordinary prose %s: %s", code, reason)
		}
	}
	for _, program := range []string{"ruby", "perl"} {
		for _, child := range []struct {
			source string
			deny   bool
		}{{"dotenvx get", true}, {"npm run env", true}, {"printf public", false}} {
			code := "`" + child.source + "`"
			if reason := Analyze(program+" -e "+shellLiteral(code), work, home, check); (reason != "") != child.deny {
				t.Errorf("backtick %s %s: reason=%q want deny=%v", program, code, reason, child.deny)
			}
		}
	}
	if reason := Analyze(`python3 -c 'import os; os.system("cd ~/.aws"); os.system("printf public")'; cat README.md`, work, home, check); reason != "" {
		t.Errorf("literal shell cwd escaped its child: %s", reason)
	}
}

func TestAudit23PyPy(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, program := range []string{"pypy", "pypy3", "pypy3.10", "pypy2.7", "pypy3.10-7.3"} {
		for _, tc := range []struct {
			code string
			deny bool
		}{
			{`import os; os.system("printenv")`, true},
			{`import subprocess; subprocess.run(['aws','ecr','get-login-password'])`, true},
			{"# public ' comment\nimport os; os.system(\"dotenvx get\")", true},
			{`open('.env').read()`, true},
			{`print('public')`, false},
			{`import subprocess; subprocess.run(['git','status'])`, false},
			{`import os; os.system('printf public')`, false},
		} {
			for _, source := range []string{
				program + " -c " + shellLiteral(tc.code),
				program + " <<'SYNTHETIC'\n" + tc.code + "\nSYNTHETIC",
				"printf '%s\\n' " + shellLiteral(tc.code) + " | " + program,
				"synthetic-launcher " + program + " -c " + shellLiteral(tc.code),
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
				}
			}
			if reason := AnalyzeArgv([]string{program, "-c", tc.code}, work, home, check); (reason != "") != tc.deny {
				t.Errorf("argv %s %s: reason=%q want deny=%v", program, tc.code, reason, tc.deny)
			}
		}
		for _, args := range []string{"-m keyring get synthetic synthetic", "-m dotenv list"} {
			if reason := Analyze(program+" "+args, work, home, check); reason == "" {
				t.Errorf("Python module printer allowed: %s %s", program, args)
			}
		}
		if reason := Analyze(program+" -m venv .venv", work, home, check); reason != "" {
			t.Errorf("public PyPy module: %s", reason)
		}
	}
}
