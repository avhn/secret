package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/search"
)

// These commands are parser inputs only, with metadata under a disposable HOME.
func TestAudit28QuotedParameterSubstitutions(t *testing.T) {
	home, work, check := audit21Fixture(t)
	var denied []string
	for _, op := range []string{":-", ":+", ":=", ":?", "-", "+", "=", "?", "/a/", "//a/", "#", "##", "%", "%%", "^", "^^", ",", ",,"} {
		for _, subst := range []string{"$(cat .env)", "$(< .env)", "`cat .env`"} {
			denied = append(denied, `echo "${x`+op+`'`+subst+`'}"`)
		}
	}
	denied = append(denied,
		`x="${y:-'$(cat .env)'}"`,
		`echo "${x['$(cat .env)']}"`,
		`echo "${x['`+"`cat .env`"+`']}"`,
		`echo "${x:-'${y:-$(cat .env)}'}"`,
		`echo "${x:-'$(echo public; else echo public)'}"`,
	)
	for _, source := range denied {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed live quoted-parameter substitution: %s", source)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
			t.Errorf("allowed argv quoted-parameter substitution: %s", source)
		}
	}
	for _, source := range []string{
		`echo "${x:-'$(cat README.md)'}"`,
		`echo "${x/a/'$(cat README.md)'}"`,
		`echo "${x:-'$(printf '%s' public)'}"`,
		`echo "${x:-'\$(cat .env)'}"`,
		`echo '${x:-$(cat .env)}'`,
		`echo ${x:-'$(cat .env)'}`,
		`echo "$(echo '$(cat .env)')"`,
		`echo "${x:-$(echo '$(cat .env)')}"`,
		`echo "${x:-'public'}"`,
		`echo "${x['$(cat README.md)']}"`,
		`echo "${x:-'` + "`cat README.md`" + `'}"`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("quoted-parameter control %s: %s", source, reason)
		}
	}
}

// This valid nested quoting shape was already conservatively denied by the
// parser's original substitution walk. Retain it rather than loosen a denial
// while adding the missing live-expansion analysis.
func TestAudit28RetainedQuotedParameterDenial(t *testing.T) {
	home, work, check := audit21Fixture(t)
	source := `echo "${x:-'$(printf '%s' '$(cat .env)')'}"`
	if reason := Analyze(source, work, home, check); reason == "" {
		t.Fatal("existing conservative quoted-parameter decision loosened")
	}
}

func TestAudit28QuotedArithmetic(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`echo $(( '$(cat .env)' ))`,
		`echo $[ '$(cat .env)' ]`,
		`echo ${x:'$(cat .env)'}`,
		`echo ${x:1:'$(cat .env)'}`,
		`echo ${x[@]:'$(cat .env)'}`,
		`echo $(( x['$(cat .env)'] ))`,
		`echo $(( 1 + '$(< .env)' ))`,
		`echo $(( '$(cat ~/.aws/credentials)' ))`,
		`echo "$(( '$(cat .env)' ))"`,
		"echo $(( '`cat .env`' ))",
		`echo $(( '1' ))`,
		`echo ${x:'1'}`,
		`(( '1' ))`,
		`for (( i='0'; i<1; i++ )); do true; done`,
	} {
		for _, wrapped := range []string{source, "bash -c " + shellLiteral(source)} {
			if reason := Analyze(wrapped, work, home, check); reason == "" {
				t.Errorf("allowed quoted arithmetic operand: %s", wrapped)
			}
		}
	}
	for _, source := range []string{
		`echo $(( 1 + 2 ))`, `echo $[ 1 + 2 ]`, `echo ${x:1:2}`,
		`echo $(( x[1] + 1 ))`, `(( x = 1 ))`,
		`for (( i=0; i<1; i++ )); do true; done`,
		`echo $(( $(printf '%s' 1) + 2 ))`,
		`echo '$(( '\''$(cat .env)'\'' ))'`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("arithmetic control %s: %s", source, reason)
		}
	}
}

func audit28ArithmeticParameterCases() []struct {
	name, source string
	deny         bool
} {
	return []struct {
		name, source string
		deny         bool
	}{
		{"default", `echo $(( ${x:-'$(cat .env)'} ))`, true},
		{"replacement", `echo $(( ${x/a/'$(cat .env)'} ))`, true},
		{"replacement_pattern", `echo $(( ${x/'$(cat .env)'/1} ))`, true},
		{"substring_offset", `echo ${a:${x:-'$(cat .env)'}}`, true},
		{"substring_length", `echo ${a:1:${x:-'$(cat .env)'}}`, true},
		{"legacy", `echo $[ ${x:-'$(cat .env)'} ]`, true},
		{"arithmetic_command", `(( x = ${x:-'$(cat .env)'} ))`, true},
		{"loop", `for (( i=${x:-'$(cat .env)'}; i<1; i++ )); do true; done`, true},
		{"index", `echo $(( x[${x:-'$(cat .env)'}] ))`, true},
		{"nested_default", `echo $(( ${x:-${y:-'$(cat .env)'}} ))`, true},
		{"backticks", "echo $(( ${x:-'`cat .env`'} ))", true},
		{"redirect_substitution", `echo $(( ${x:-'$(< .env)'} ))`, true},
		{"double_quotes", `echo $(( ${x:-"$(cat .env)"} ))`, true},
		{"unquoted_default", `echo $(( ${x:-1} + 2 ))`, false},
		{"unquoted_replacement", `echo $(( ${x/a/1} ))`, false},
		{"unquoted_offset", `echo ${a:${x:-1}}`, false},
		{"command_quoting", `echo $(( $(printf '%s' 1) + 2 ))`, false},
		{"default_command_quoting", `echo $(( ${x:-$(printf '%s' 1)} ))`, false},
		{"non_arithmetic_default", `echo ${x:-'$(cat .env)'}`, false},
	}
}

func TestAudit28NestedArithmeticParameters(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range audit28ArithmeticParameterCases() {
		t.Run(tc.name, func(t *testing.T) {
			if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("shell: reason=%q, want deny=%v", reason, tc.deny)
			}
			if reason := AnalyzeArgv([]string{"bash", "-c", tc.source}, work, home, check); (reason != "") != tc.deny {
				t.Errorf("argv: reason=%q, want deny=%v", reason, tc.deny)
			}
		})
	}
}

// Like the paired audit 27 review, opt in with a freshly built binary. Candidate
// source is sent only as JSON to the guards, never executed by a shell. Both Go
// adapters cover every case; Bash parity covers the three confirmed witnesses.
func TestAudit28PairedNestedArithmeticParameters(t *testing.T) {
	binary := os.Getenv("SECRET_AUDIT28_BINARY")
	if binary == "" {
		t.Skip("set SECRET_AUDIT28_BINARY to a fresh absolute Go binary for paired adapter checks")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("SECRET_AUDIT28_BINARY must be absolute")
	}
	home, work, _ := audit21Fixture(t)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(cwd, "..", "..", "..", "hooks", "guard-secrets")
	for _, tc := range audit28ArithmeticParameterCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, host := range []string{"claude", "codex"} {
				for _, command := range []any{tc.source, []string{"bash", "-c", tc.source}} {
					envelope, err := json.Marshal(map[string]any{
						"hook_event_name": "PreToolUse", "cwd": work, "tool_name": "Bash",
						"tool_input": map[string]any{"command": command},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, implementation := range []string{"bash", "go"} {
						if implementation == "bash" {
							switch tc.name {
							case "default", "replacement", "substring_offset":
							default:
								continue
							}
						}
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
								HookSpecificOutput struct{ PermissionDecision string }
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

func TestAudit28ReservedWordFraming(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`echo public; else echo public`,
		`echo public; in echo public`,
		`if true; then :; else :; else :; fi`,
	} {
		for _, wrapped := range []string{
			source, "( " + source + " )", "{ " + source + "; }",
			"f() { " + source + "; }", "echo $(" + source + ")",
			"bash -c " + shellLiteral(source), "sh -c " + shellLiteral(source),
		} {
			if reason := Analyze(wrapped, work, home, check); reason == "" {
				t.Errorf("allowed misplaced reserved word: %s", wrapped)
			}
		}
	}
	for _, source := range []string{
		`echo else in`, `'else' public`, `"in" public`, `\else public`, `\in public`,
		`if true; then :; elif false; then :; else :; fi`,
		`for x in public; do echo "$x"; done`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("reserved-word control %s: %s", source, reason)
		}
	}
}

func TestAudit28CommandlessCoproc(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`coproc > public.out`, `coproc 1>&1`, `coproc 2>public.out`, `coproc 22<README.md`,
		`echo public; coproc > public.out`,
	} {
		for _, wrapped := range []string{source, "( " + source + " )", "bash -c " + shellLiteral(source)} {
			if reason := Analyze(wrapped, work, home, check); reason == "" {
				t.Errorf("allowed commandless coprocess: %s", wrapped)
			}
		}
	}
	for _, source := range []string{
		`coproc true`, `coproc { true; }`, `coproc SYNTHETIC { true; }`,
		`coproc ( true )`, `coproc SYNTHETIC ( true )`,
		`coproc true > public.out`, `coproc SYNTHETIC { true; } > public.out`,
		`coproc 1 > public.out`, `coproc '1'>public.out`, `coproc \1>public.out`,
		`> public.out`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("coprocess control %s: %s", source, reason)
		}
	}
}

func TestAudit28RootGlobSelectors(t *testing.T) {
	home, work, check := audit21Fixture(t)
	checkDeadline := func(start time.Time) {
		t.Helper()
		if elapsed := time.Since(start); elapsed >= 2*time.Second {
			t.Errorf("root glob decision exceeded deadline: %s", elapsed)
		}
	}
	for _, tc := range []struct {
		glob string
		want bool
	}{
		{"/", false}, {"//", false}, {"///", false}, {"{a,/}", false},
		{"{/,.env}", true}, {"{/,*.env}", true}, {"src/*.env", true},
		{strings.Repeat("{", 18) + "/" + strings.Repeat("}", 18), true},
	} {
		start := time.Now()
		if got := search.Selector(tc.glob); got != tc.want {
			t.Errorf("selector %q = %v, want %v", tc.glob, got, tc.want)
		}
		checkDeadline(start)
	}
	for _, glob := range []string{"/", "//", "{a,/}", "{/,.env}", "{/,*.env}"} {
		// Grep must always decide; protected literal re-inclusions must deny.
		start := time.Now()
		reason := search.ToolGrep("", glob, "", "content", work, home)
		checkDeadline(start)
		if strings.Contains(glob, ".env") && reason == "" {
			t.Errorf("Grep allowed protected re-inclusion %q", glob)
		}
	}
	for _, source := range []string{`rg -g / x`, `rg -g // x`, `fd -g / .`, `fd -g // .`} {
		start := time.Now()
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("root glob control %s: %s", source, reason)
		}
		checkDeadline(start)
	}
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{`rg -g "/" -g "*.env" TOKEN`, `rg -g '{/,.env}' TOKEN`} {
		start := time.Now()
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed protected glob re-inclusion: %s", source)
		}
		checkDeadline(start)
	}
}
