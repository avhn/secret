package policy

import (
	"strings"
	"testing"
)

// All launch source is analyzer data, never code executed by the tests.
func TestAudit25TemplateInterpolation(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, runtime := range []struct{ name, flag, stdin string }{
		{"node", "-e", "node"}, {"nodejs", "-e", "nodejs"},
		{"bun", "-e", "bun"}, {"deno", "eval", "deno run --allow-run -"},
	} {
		for _, tc := range []struct {
			code string
			deny bool
		}{
			{"require(\"child_process\").execSync(`echo ${require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"])}`)", true},
			{"console.log(`public ${require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"])}`)", true},
			{"console.log(`outer ${`inner ${require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"])}`}`)", true},
			{"console.log(`public ${({value:require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"])}).value}`)", true},
			{"console.log(`public ${/* } */ require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"])}`)", true},
			{"console.log(`public ${/}/.test('}') ? require(\"child_process\").execFileSync(\"gh\",[\"auth\",\"token\"]) : 'ok'}`)", true},
			{"require(\"child_process\").execSync(`echo ${require(\"child_process\").execFileSync(\"cat\",[\"README.md\"])}`)", false},
			{"console.log(`public ${'hello'}`)", false},
			{"console.log(`outer ${`inner ${'public'}`}`)", false},
			{"console.log(`public ${({value:'}'}).value}`)", false},
			{"console.log(`public ${/}/.test('}')}`)", false},
			{"console.log(`public ${'execFileSync(\"gh\",[\"auth\",\"token\"])'}`)", false},
			{"console.log(`public \\${execFileSync(\"gh\",[\"auth\",\"token\"])}`)", false},
		} {
			for _, source := range []string{
				runtime.name + " " + runtime.flag + " " + shellLiteral(tc.code),
				runtime.stdin + " <<'SYNTHETIC'\n" + tc.code + "\nSYNTHETIC",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
				}
			}
			if reason := AnalyzeArgv([]string{runtime.name, runtime.flag, tc.code}, work, home, check); (reason != "") != tc.deny {
				t.Errorf("argv %s %s: reason=%q want deny=%v", runtime.name, tc.code, reason, tc.deny)
			}
		}
	}
	for _, code := range []string{
		"console.log(`public ${'unterminated')",
		"console.log(`public ${" + strings.Repeat("{", 70) + "0" + strings.Repeat("}", 70) + "}`)",
		"console.log(`public ${" + strings.Repeat("`nested ${", 6) + "'ok'" + strings.Repeat("}`", 6) + "}`)",
	} {
		if reason := AnalyzeArgv([]string{"node", "-e", code}, work, home, check); reason == "" {
			t.Errorf("unbounded or incomplete interpolation allowed: %s", code)
		}
	}
}

func TestAudit25FallbackFramingParity(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"ansible localhost -a 'printenv TOKEN\nif true; then'", true},
		{"ansible localhost -a 'gh auth token\nif true; then'", true},
		{"ansible localhost -a 'echo public\ngh auth token\nif true; then'", true},
		{"ansible localhost -a 'echo public\nif true; then'", false},
		{"ansible localhost -a 'echo hello (world)'", false},
		{"ansible localhost -a \"bash -c 'true &&'\"", true},
		{"ansible localhost -a \"bash -c 'true && true'\"", false},
		{"python3 <<'CODE'\nprint(\"$UNKNOWN $(printf public) `printf public`\")\nCODE", false},
		{"python3 <<'CODE'\nprint(\"$UNKNOWN $(gh auth token) `printf public`\")\nCODE", true},
	} {
		if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.source, reason, tc.deny)
		}
	}
}

func TestAudit25MakeClusterOperands(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		"make --eval 'public:; echo ok' -sE 'public:; gh auth token'",
		"gmake -E 'public:; echo ok' -sE 'public:; gh auth token'",
		"make --eval 'public:; echo ok' -sE'public:; gh auth token'",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("later clustered recipe allowed: %s", source)
		}
	}
	for _, source := range []string{
		"make --eval 'public:; echo ok' -sE 'public:; cat README.md'",
		"gmake -E 'public:; echo ok' -nsE'public:; echo ok'",
		"make -sCpublic -j4 -sE 'public:; echo ok'",
		"make -sfREADME.md -sE 'public:; echo ok'",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public clustered recipe denied %s: %s", source, reason)
		}
	}
}
