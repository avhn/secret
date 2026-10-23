package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// All candidates are JSON data for both adapters, never shell commands to run.
// The fixture contains only synthetic files below a disposable HOME/work root.
func TestOverDenialFollowupAdapters(t *testing.T) {
	home, work := audit28ToolsFixture(t)
	aws := filepath.Join(home, ".aws")
	if err := os.MkdirAll(aws, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(aws, "credentials"), filepath.Join(work, ".env")} {
		if err := os.WriteFile(name, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 128; i++ {
		if err := os.Mkdir(filepath.Join(work, fmt.Sprintf("d%d", i)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	chain := func(n int) string {
		var commands []string
		for i := 0; i < n; i++ {
			commands = append(commands, fmt.Sprintf("cd d%d", i))
		}
		return strings.Join(commands, " || ")
	}
	quotedAWS := audit26Shell([]string{aws})
	type reviewCase struct {
		name, source string
		deny         bool
	}
	cases := []reviewCase{
		{"cd public beyond old cap", chain(40) + "; ls", false},
		{"cd protected first alternative", "cd " + quotedAWS + " || " + chain(40) + "; cat credentials", true},
		{"cd protected last alternative", chain(40) + " || cd " + quotedAWS + "; cat credentials", true},
		{"cd protected last at cap", chain(126) + " || cd " + quotedAWS + "; cat credentials", true},
		{"cd protected beyond cap", chain(127) + " || cd " + quotedAWS + "; cat credentials", true},
		{"cd retained failure cwd", chain(40) + "; cat .env", true},
		{"cd failed final and", chain(40) + " && cd missing; cat .env", true},
		{"cd pipeline retains parent", "(" + chain(40) + ") | true; cat .env", true},
		{"cd negated child retains parent", "! (" + chain(40) + "); cat .env", true},
		{"cd later nested shell", chain(40) + "; bash -c 'cat ~/.aws/credentials'", true},
		{"cd relative protected suffix", chain(40) + " || cd " + audit26Shell([]string{home}) + "; cd .aws && cat credentials", true},
		{"quoted decimal", `(( "1" + 2 ))`, false},
		{"quoted index", `((a["0"]++))`, false},
		{"quoted loop", `for ((i="0";i<"2";a["0"]++)); do :; done`, false},
		{"quoted function index", `function f ((a["0"]++)); f`, false},
		{"quoted later reader", `(( "1" )); cat ~/.aws/credentials`, true},
		{"quoted nested literal then reader", `echo "$(printf 1)"; (( "1" )); cat .env`, true},
		{"quoted numeric substitution", `(( "$(printf 1)" ))`, true},
		{"quoted recursive output", `(( "$(printf 'a[$(cat ~/.aws/credentials)]')" ))`, true},
		{"quoted backquote output", "(( \"`printf 'a[$(cat ~/.aws/credentials)]'`\" ))", true},
		{"quoted index output", `((a["$(printf 'a[$(cat ~/.aws/credentials)]')"]++))`, true},
		{"quoted loop output", `for ((i="$(printf 'a[$(cat ~/.aws/credentials)]')";i<2;i++)); do :; done`, true},
		{"quoted process operand", `(( "1" + <(cat ~/.aws/credentials) ))`, true},
		{"quoted parameter operand", `operand='a[$(cat ~/.aws/credentials)]'; (( "1" + "$operand" ))`, true},
		{"quoted stored operand", `operand='a[$(cat ~/.aws/credentials)]'; (( "1" + operand ))`, true},
		{"quoted stored array operand", `a='b[$(cat ~/.aws/credentials)]'; (( a["0"] ))`, true},
		{"quoted unknown writer", `read operand; (( "1" + operand ))`, true},
		{"quoted integer bind", `declare -i n; n="$(printf 'a[$(cat ~/.aws/credentials)]')"; (( "1" ))`, true},
		{"quoted identifier concatenation", `x1='a[$(cat ~/.aws/credentials)]'; (( x"1" ))`, true},
		{"quoted escaped output", `(( "a[\$(cat ~/.aws/credentials)]" ))`, true},
		{"quoted single expansion", `(( '1$(cat ~/.aws/credentials)' ))`, true},
		{"quoted literal before protected loop body", `for ((i="0";i<"2";i++)); do cat ~/.aws/credentials; done`, true},
		{"workspace old bound", `pnpm --filter '*' exec cat config.txt`, true},
		{"workspace protected reader", `pnpm --filter '*' exec cat ~/.aws/credentials`, true},
	}
	if err := os.Symlink(aws, filepath.Join(work, "aws-link")); err == nil {
		cases = append(cases,
			reviewCase{"cd symlink alternative", chain(40) + " || cd aws-link; cat credentials", true},
			reviewCase{"cd relative bind source", chain(40) + "; docker run -v ./aws-link:/data image cat /data/credentials", true})
	} else {
		t.Logf("symlink review cases unavailable: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range []any{tc.source, []string{"bash", "-c", tc.source}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, tc.deny)
			}
		})
	}
}
