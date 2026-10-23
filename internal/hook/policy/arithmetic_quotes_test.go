package policy

import (
	"testing"

	"github.com/avhn/secret/internal/hook/roles"
)

// Synthetic parser inputs only. Arithmetic commands and C-style loop clauses
// accept whole double-quoted decimal constants. Single quotes and expansion
// operands retain their existing denial, even when a child prints only digits.
func TestArithmeticCommandQuotedOperands(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		name, source string
		deny         bool
	}{
		{"double quoted number", `(( "1" + 2 ))`, false},
		{"single quoted number", `(( '1' + 2 ))`, true},
		{"leading zero", `(( "01" ))`, false},
		{"quoted index", `((a["0"]++))`, false},
		{"quoted loop", `for ((i="0";i<"2";a["0"]++)); do :; done`, false},
		{"single quoted loop", `for (( i='0'; i<1; i++ )); do true; done`, true},
		{"quoted public child", `(( "$(printf 1)" + 2 ))`, true},
		{"quoted increment target", `(("1"++))`, true},
		{"empty quoted index", `((a[""]++))`, true},
		{"quoted loop separators", `for (("0;1;2")); do :; done`, true},
		{"quoted expression", `(( "1 + 2" ))`, true},
		{"quoted identifier", `(( "x" ))`, true},
		{"quoted assignment target", `(( "IFS" = 1 ))`, true},
		{"concatenated prefix", `(( x"1" ))`, true},
		{"concatenated suffix", `(( "1"x ))`, true},
		{"ansi c quote", `(( $'1' ))`, true},
		{"locale quote", `(( $"1" ))`, true},
		{"parameter default", `(( ${x:-"1"} ))`, true},
		{"parameter default index", `(( a[${x:-'1'}] ))`, true},
		{"nested expansion", `(( $(( "1" )) + 1 ))`, true},
		{"arithmetic expansion", `echo $(( "1" + 2 ))`, true},
		{"slice offset", `echo ${x:"1"}`, true},
		{"protected child", `(( "$(cat .env)" + 2 ))`, true},
		{"protected redirect child", `(( "$(< .env)" ))`, true},
		{"protected home child", `(( "$(cat ~/.aws/credentials)" ))`, true},
		{"protected backquote child", "(( \"`cat .env`\" ))", true},
		{"protected index child", `((a["$(cat .env)"]++))`, true},
		{"protected loop child", `for ((i="$(cat .env)";i<2;i++)); do :; done`, true},
		{"reevaluated child output", `(( "$(printf 'a[$(cat .env)]')" ))`, true},
		{"single quoted subscript child", `(( 'a[$(cat .env)]' ))`, true},
		{"single quoted child", `(( '$(cat .env)' + 1 ))`, true},
		{"single quoted digit child", `(( '1$(cat .env)' ))`, true},
		{"single quoted index child", `((a['$(cat .env)']++))`, true},
		{"single quoted loop child", `for ((i='$(cat .env)';i<1;i++)); do :; done`, true},
		{"escaped subscript child", `(( "a[\$(cat .env)]" ))`, true},
		{"escaped child", `(( "\$(cat .env)" ))`, true},
		{"later protected read", `(( "1" )); cat .env`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze(tc.source, work, home, check); (got != "") != tc.deny {
				t.Errorf("source=%q denial=%q want deny=%v", tc.source, got, tc.deny)
			}
			// Explicit-shell argv retains the same literal arithmetic proof.
			wrapped := "bash -c " + shellLiteral(tc.source)
			if got := Analyze(wrapped, work, home, check); (got != "") != tc.deny {
				t.Errorf("wrapped source=%q denial=%q want deny=%v", wrapped, got, tc.deny)
			}
		})
	}
}

// The parser still cannot read `time --` before an arithmetic command.
func TestArithmeticRetainedControls(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`time -- ((i++))`,
	} {
		if got := Analyze(source, work, home, check); got != roles.Indeterminate {
			t.Errorf("source=%q denial=%q want %q", source, got, roles.Indeterminate)
		}
	}
}
