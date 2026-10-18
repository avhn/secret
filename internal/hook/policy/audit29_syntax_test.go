package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// All command strings are analyzer or JSON guard inputs, never executed.
func TestAudit29ExtglobSubstitutions(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, op := range []string{"@", "+", "!", "*", "?"} {
		for _, body := range []string{"$(cat .env)", "$(cat ~/.aws/credentials)", "`cat .env`", "a|$(gh auth token)", "<(cat .env)", ">(cat .env)", "$(if)", "$(;;)", "`fi`", "${x", "$(echo \")", "$(cat <<E)"} {
			pattern := op + "(" + body + ")"
			for _, source := range []string{
				"[[ x == " + pattern + " ]]", "[[ x != " + pattern + " ]]",
				"case x in " + pattern + ") true;; esac", "echo ${x/" + pattern + "/public}",
			} {
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("allowed opaque extglob expansion: %s", source)
				}
				if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
					t.Errorf("allowed argv extglob expansion: %s", source)
				}
			}
		}
		for _, body := range []string{"a|b", "$(cat README.md)", "`cat README.md`", "$(printf '%s' public)"} {
			source := "[[ x == " + op + "(" + body + ") ]]"
			if reason := Analyze(source, work, home, check); reason != "" {
				t.Errorf("public extglob control %s: %s", source, reason)
			}
		}
	}
	for _, source := range []string{`[[ x == '@($(cat .env))' ]]`, `echo '@($(cat .env))'`} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert extglob control %s: %s", source, reason)
		}
	}
}

func audit29Backquote(source string) string {
	return "`" + strings.NewReplacer(`\`, `\\`, "`", "\\`").Replace(source) + "`"
}

func TestAudit29NestedBackquotes(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, inner := range []string{"cat .env", "cat ~/.aws/credentials", "env", "if", "fi", "|"} {
		for _, compound := range []string{"(echo %s)", "{ echo %s; }", "if true; then echo %s; fi", "for x in a; do echo %s; done"} {
			body := fmt.Sprintf(compound, audit29Backquote(inner))
			for depth := 3; depth <= 5; depth++ {
				nested := body
				for level := 1; level < depth; level++ {
					nested = "echo " + audit29Backquote(nested)
				}
				if reason := Analyze(nested, work, home, check); reason == "" {
					t.Errorf("allowed depth-%d compound backquote: %s", depth, nested)
				}
				if reason := AnalyzeArgv([]string{"bash", "-c", nested}, work, home, check); reason == "" {
					t.Errorf("allowed depth-%d argv backquote", depth)
				}
			}
		}
	}
	for _, source := range []string{"echo `cat README.md`", "echo `echo \\`cat README.md\\``", "echo '\\`cat .env\\`'", "echo \\`cat .env\\`"} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("backquote control %s: %s", source, reason)
		}
	}
}

func TestAudit29ReevaluatedAssignments(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, value := range []string{"a[$(cat .env)]", "a[`cat .env`]", "a[$(cat ~/.aws/credentials)]", "a[$(if)]", "${y:-a[$(cat .env)]}"} {
		for _, expression := range []string{"echo $(($x))", "echo $(( $x + 1 ))", "echo $((x))", "echo $[x]", "(( x ))", "let x", "let \"$x\"", "declare -i n=x", "y=x; echo $((y))", "echo ${a:x}", "echo ${a:1:x}", "echo ${a[x]}", "a[x]=public", "[[ x -eq 1 ]]", "[[ $x -eq 1 ]]", "for ((i=x; i<1; i++)); do true; done"} {
			source := "x=" + shellLiteral(value) + "; " + expression
			if reason := Analyze(source, work, home, check); reason == "" {
				t.Errorf("allowed arithmetic re-evaluation: %s", source)
			}
			if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
				t.Errorf("allowed argv arithmetic re-evaluation: %s", source)
			}
		}
	}
	for _, declaration := range []string{"local -a", "local -A", "declare -a", "typeset -a"} {
		for _, value := range []string{"(`cat .env`)", "($(cat .env))", "($(if))"} {
			source := "f() { " + declaration + " x=" + shellLiteral(value) + "; }; f"
			if reason := Analyze(source, work, home, check); reason == "" {
				t.Errorf("allowed compound-assignment re-evaluation: %s", source)
			}
		}
	}
	for _, source := range []string{
		`x='a[$(cat .env)]'; echo "$x"`, `x='a[$(cat .env)]'; echo $((1 + 2))`,
		`x=1; echo $((x + 1))`, `x='1 + 2'; echo $(($x))`,
		"a=('$(cat .env)' '`cat .env`')", `declare -a a=('$(cat .env)')`,
		`f() { local -a x='(public data)'; }; f`, `[[ public == public ]]`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert re-evaluation control %s: %s", source, reason)
		}
	}
}

func audit29ArithmeticStateCases() []struct{ name, source string } {
	return []struct{ name, source string }{
		{"single loop item", `for x in 'a[$(cat .env)]'; do echo $((x)); done`},
		{"later loop item", `for x in 0 'a[$(cat .env)]'; do echo $(($x)); done`},
		{"loop identifier chain", `y='a[$(cat .env)]'; for x in 0 y; do echo $((x)); done`},
		{"loop result", `for x in 0 'a[$(cat .env)]'; do true; done; echo $((x))`},
		{"nested loop binding", `for x in 0 'a[$(cat .env)]'; do for y in "$x"; do echo $((y)); done; done`},
		{"loop scalar copy", `for x in 0 'a[$(cat .env)]'; do y="$x"; echo $((y)); done`},
		{"reassigned loop source", `y=0; y='a[$(cat .env)]'; for x in "$y"; do echo $((x)); done`},
		{"reassignment", `x=0; x='a[$(cat .env)]'; echo $(($x))`},
		{"overwritten active value", `x='a[$(cat .env)]'; x=0; echo $((x))`},
		{"overwritten identifier", `y='a[$(cat .env)]'; x=y; x=0; echo $((x))`},
		{"reassigned scalar copy", `y=0; y='a[$(cat .env)]'; x="$y"; echo $((x))`},
		{"expanded append", `y='$(cat .env)]'; x='a['; x+="$y"; echo $((x))`},
		{"append", `x='a['; x+='$(cat .env)]'; echo $(($x))`},
		{"append after reassignment", `x=0; x='a['; x+='$'; x+='(cat .env)]'; echo $((x))`},
		{"split substitution append", `x='a[$'; x+='(cat .env)]'; echo $((x))`},
		{"active first branch", `if true; then x='a[$(cat .env)]'; else x=0; fi; echo $(($x))`},
		{"active later branch", `if true; then x=0; else x='a[$(cat .env)]'; fi; echo $((x))`},
	}
}

func TestAudit29ArithmeticState(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, test := range audit29ArithmeticStateCases() {
		t.Run(test.name, func(t *testing.T) {
			if reason := Analyze(test.source, work, home, check); reason == "" {
				t.Error("allowed arithmetic re-evaluation after state transition")
			}
			if reason := AnalyzeArgv([]string{"bash", "-c", test.source}, work, home, check); reason == "" {
				t.Error("allowed argv arithmetic re-evaluation after state transition")
			}
		})
	}
	for _, source := range []string{
		`for x in 0 1 2; do echo $((x)); done`,
		`for x in 'a[$(cat .env)]'; do echo "$x"; done`,
		`x=0; x=1; echo $((x))`, `x=1; x+=2; echo $((x))`,
		`if true; then x=0; else x=1; fi; echo $((x))`,
		`x=0; x='a[$(cat .env)]'; echo "$x"`,
		`x='a['; x+='$(cat .env)]'; echo $((1 + 2))`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert state control %s: %s", source, reason)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason != "" {
			t.Errorf("inert argv state control %s: %s", source, reason)
		}
	}
}

func TestAudit29ArithmeticStateBudgets(t *testing.T) {
	for _, budget := range []string{"alternatives", "bytes", "unknown loop"} {
		t.Run(budget, func(t *testing.T) {
			a := &analyzer{deadline: time.Now().Add(time.Second)}
			switch budget {
			case "alternatives":
				for i := 0; i < 65; i++ {
					a.noteArithmeticValue("x", fmt.Sprint(i))
				}
			case "bytes":
				a.noteArithmeticValue("x", strings.Repeat("0", 40<<10))
				a.noteArithmeticAppend("x", "0")
			case "unknown loop":
				a.noteArithmeticUnknown("x")
			}
			// A later harmless assignment or append cannot erase uncertainty.
			a.noteArithmeticValue("x", "0")
			a.noteArithmeticAppend("x", "0")
			if values, assigned := a.arithmeticValues["x"]; !assigned || values != nil {
				t.Fatalf("lost exhausted binding: assigned=%v values=%v", assigned, values)
			}
			a.reevaluatedArithmetic(&syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: "x"}}})
			if a.reason != roles.Indeterminate {
				t.Errorf("uncertain binding certified arithmetic: %q", a.reason)
			}
		})
	}
}

func TestAudit29ArithmeticLiteralChildState(t *testing.T) {
	home, work, check := audit21Fixture(t)
	a := &analyzer{home: home, cwd: work, protected: check, deadline: time.Now().Add(time.Second), env: map[string]string{"x": ""}}
	a.noteArithmeticValue("x", "0")
	a.noteArithmeticValue("x", "a[$(cat .env)]")
	child := a.literalChild(work)
	child.noteArithmeticValue("y", "1")
	child.fragment("echo $((x))", 0)
	if child.reason == "" {
		t.Error("literal child lost inherited arithmetic alternatives")
	}
	if _, assigned := a.arithmeticValues["y"]; assigned || a.reason != "" {
		t.Error("literal child changed parent arithmetic state")
	}
}

func TestAudit29AdapterArithmeticState(t *testing.T) {
	binary := os.Getenv("SECRET_AUDIT29_BINARY")
	if binary == "" {
		t.Skip("set SECRET_AUDIT29_BINARY to a fresh absolute Go binary for adapter checks")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("SECRET_AUDIT29_BINARY must be absolute")
	}
	_, work, _ := audit21Fixture(t)
	for _, host := range []string{"claude", "codex"} {
		for _, test := range audit29ArithmeticStateCases() {
			for _, argv := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/argv=%v", host, test.name, argv), func(t *testing.T) {
					var command any = test.source
					if argv {
						command = []string{"bash", "-c", test.source}
					}
					payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": work, "tool_input": map[string]any{"command": command}})
					if err != nil {
						t.Fatal(err)
					}
					cmd := syntheticCommand(t, binary, "hook", host)
					cmd.Dir, cmd.Stdin = work, bytes.NewReader(payload)
					var output, stderr bytes.Buffer
					cmd.Stdout, cmd.Stderr = &output, &stderr
					if err := cmd.Run(); err != nil || stderr.Len() != 0 {
						t.Fatalf("error=%v stderr=%q", err, stderr.String())
					}
					var decision struct {
						HookSpecificOutput struct{ PermissionDecision string }
					}
					if err := json.Unmarshal(output.Bytes(), &decision); err != nil || decision.HookSpecificOutput.PermissionDecision != "deny" {
						t.Errorf("allowed arithmetic state transition: %q", output.String())
					}
				})
			}
		}
	}
}

func TestAudit29QuotedCompoundAssignments(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, declaration := range []string{"local -a", "local -A", "declare -a", "typeset -a"} {
		for _, test := range []struct {
			name, prefix, operand string
		}{
			{"quoted operand", "", "'a=(`cat .env`)'"},
			{"static parameter", "x='(`cat .env`)'; ", `a="$x"`},
			{"braced parameter", "x='($(cat .env))'; ", `a="${x}"`},
			{"quoted expanded operand", "x='(`cat .env`)'; ", `"a=$x"`},
			{"expanded operand", "x='a=(`cat .env`)'; ", `"$x"`},
			{"concatenated value", "x='`cat .env`'; ", `a="("$x")"`},
		} {
			t.Run(declaration+"/"+test.name, func(t *testing.T) {
				source := test.prefix + "f() { " + declaration + " " + test.operand + "; }; f"
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("allowed normalized compound assignment: %s", source)
				}
				if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
					t.Errorf("allowed argv normalized compound assignment: %s", source)
				}
			})
		}
	}
	for _, source := range []string{
		`f() { local -a 'a=(public data)'; }; f`,
		`x='(public data)'; f() { local -a a="$x"; }; f`,
		`x='(public data)'; f() { local -a "a=$x"; }; f`,
		`x='a=(public data)'; f() { local -a "$x"; }; f`,
		`x='(` + "`cat .env`" + `)'; f() { local a="$x"; }; f`,
		`declare -a a=('$(cat .env)' '` + "`cat .env`" + `')`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert normalized assignment control %s: %s", source, reason)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason != "" {
			t.Errorf("inert argv normalized assignment control %s: %s", source, reason)
		}
	}
}

func TestAudit29DeclarationNormalization(t *testing.T) {
	for _, test := range []struct{ source, want string }{
		{`'a=(` + "`cat .env`" + `)'`, "a=(`cat .env`)"},
		{`a="$x"`, "a=(`cat .env`)"},
		{`"a=${x}"`, "a=(`cat .env`)"},
		{`a=\($y\)`, "a=($x)"},
		{`a="\\$y"`, `a=\$x`},
		{`a=$'\x28public\x29'`, "a=(public)"},
		{`a='* ? ~ public'`, "a=* ? ~ public"},
		{`a=''`, "a="},
	} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader("echo "+test.source), "")
		if err != nil {
			t.Fatal(err)
		}
		a := &analyzer{env: map[string]string{"x": "(`cat .env`)", "y": "$x"}, deadline: time.Now().Add(time.Second)}
		word := file.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		if got, known := a.declarationReevaluationValue(word); !known || got != test.want || a.reason != "" {
			t.Errorf("%s: got=%q known=%v reason=%q want=%q", test.source, got, known, a.reason, test.want)
		}
	}
	for _, budget := range []string{"bytes", "steps", "deadline"} {
		t.Run(budget, func(t *testing.T) {
			a := &analyzer{deadline: time.Now().Add(time.Second)}
			word := &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: "public"}}}
			switch budget {
			case "bytes":
				a.env = map[string]string{"x": strings.Repeat("public", 7000)}
				word.Parts = []syntax.WordPart{&syntax.ParamExp{Param: &syntax.Lit{Value: "x"}}}
			case "steps":
				for i := 0; i < 256; i++ {
					word.Parts = append(word.Parts, &syntax.SglQuoted{Value: "public"})
				}
			case "deadline":
				a.deadline = time.Now().Add(-time.Second)
			}
			if _, known := a.declarationReevaluationValue(word); known || a.reason != roles.Indeterminate {
				t.Errorf("exhausted normalization budget: known=%v reason=%q", known, a.reason)
			}
		})
	}
}

func TestAudit29AdapterCompoundAssignments(t *testing.T) {
	binary := os.Getenv("SECRET_AUDIT29_BINARY")
	if binary == "" {
		t.Skip("set SECRET_AUDIT29_BINARY to a fresh absolute Go binary for adapter checks")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("SECRET_AUDIT29_BINARY must be absolute")
	}
	_, work, _ := audit21Fixture(t)
	for _, host := range []string{"claude", "codex"} {
		for _, source := range []string{
			"f() { local -a 'x=(`cat .env`)'; }; f",
			"x='(`cat .env`)'; f() { local -a a=\"$x\"; }; f",
		} {
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": work, "tool_input": map[string]any{"command": source}})
			if err != nil {
				t.Fatal(err)
			}
			cmd := syntheticCommand(t, binary, "hook", host)
			cmd.Dir, cmd.Stdin = work, bytes.NewReader(payload)
			var output, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &stderr
			if err := cmd.Run(); err != nil || stderr.Len() != 0 {
				t.Fatalf("%s: error=%v stderr=%q", host, err, stderr.String())
			}
			var decision struct {
				HookSpecificOutput struct{ PermissionDecision string }
			}
			if err := json.Unmarshal(output.Bytes(), &decision); err != nil || decision.HookSpecificOutput.PermissionDecision != "deny" {
				t.Errorf("%s allowed compound assignment %s: %q", host, source, output.String())
			}
		}
	}
}

func TestAudit29DotDirectoryGlobs(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, name := range []string{".aws/config", ".ssh/id_rsa", ".docker/config.json", ".config/gh/hosts.yml", "public/README.md", ".public/README.md"} {
		name = filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, prefix := range []string{"", "shopt -s dotglob; ", "GLOBIGNORE=x; ", "export GLOBIGNORE=.; ", "f() { shopt -s dotglob; }; f; "} {
		for _, operand := range []string{"~/*/credentials", "~/?aws/credentials", "~/[.]aws/credentials", "~/*/id_rsa", "~/*/config.json", "~/*/gh/hosts.yml", "~/*/*/hosts.yml", "~/**/credentials"} {
			source := prefix + "cat " + operand
			if reason := Analyze(source, work, home, check); reason == "" {
				t.Errorf("allowed hidden-directory glob: %s", source)
			}
			if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
				t.Errorf("allowed argv hidden-directory glob: %s", source)
			}
		}
	}
	for _, source := range []string{
		`bash -O dotglob -c 'cat ~/*/credentials'`, `env BASHOPTS=dotglob bash -c 'cat ~/*/credentials'`,
		`GLOBIGNORE=x bash -c 'cat ~/*/credentials'`, `zsh -c 'setopt globdots; cat ~/*/credentials'`,
		`shopt -s dotglob; cp ~/*/credentials copy.txt`, `shopt -s dotglob; head -n 50 ~/?aws/credentials`,
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed dotglob wrapper: %s", source)
		}
	}
	if reason := AnalyzeArgv([]string{"bash", "-O", "dotglob", "-c", "cat ~/*/credentials"}, work, home, check); reason == "" {
		t.Error("allowed dotglob shell argv")
	}
	for _, source := range []string{`cat ~/*/README.md`, `shopt -s dotglob; cat ~/*/README.md`, `cat ~/public/*`, `echo '~/*/credentials'`, `cat '~/*/credentials'`} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public glob control %s: %s", source, reason)
		}
	}
}

func audit29ManyLiterals() string {
	var source strings.Builder
	for i := 0; i < 70000; i++ {
		fmt.Fprintf(&source, "f('w%d')\n", i)
	}
	return source.String()
}

func TestAudit29InterpreterLiteralDeadline(t *testing.T) {
	home, work, check := audit21Fixture(t)
	body := audit29ManyLiterals()
	for _, language := range []string{"python3", "node", "ruby", "perl", "php", "lua"} {
		start := time.Now()
		reason := Analyze(language+" - <<'EOF'\n"+body+"EOF\n", work, home, check)
		if reason == "" {
			t.Errorf("%s allowed over-budget literal source", language)
		}
		if elapsed := time.Since(start); elapsed >= 2500*time.Millisecond {
			t.Errorf("%s decision exceeded deadline: %s", language, elapsed)
		}
	}
}

func TestAudit29BodyScanBoundaries(t *testing.T) {
	for _, token := range []string{".env", ".env.example", ".env.template", ".aws/credentials", ".git/config", ".git", ".gitname", "app.secret", "app.secretname"} {
		for _, offset := range []int{8180, 8191, 8192, 8193, 8448 - len(token), 8447, 8448, 8449} {
			code := strings.Repeat(" ", offset) + token + " public"
			a := &analyzer{deadline: time.Now().Add(time.Second)}
			want := hasProtectedLiteral(code) || gitToken.MatchString(code)
			if got := a.protectedBodyLiteral(code); got != want {
				t.Fatalf("offset=%d token=%s: protected=%v want=%v", offset, token, got, want)
			}
		}
	}
	for _, prefix := range []string{".env.", ".ssh/id_"} {
		code := prefix + strings.Repeat("a", 17000) + " public"
		a := &analyzer{deadline: time.Now().Add(time.Second)}
		if !hasProtectedLiteral(code) || !a.protectedBodyLiteral(code) {
			t.Errorf("unbounded credential suffix lost its witness: %s", prefix)
		}
	}
	now := time.Now()
	a := &analyzer{deadline: now.Add(time.Second), now: func() time.Time {
		now = now.Add(600 * time.Millisecond)
		return now
	}}
	if !a.protectedBodyLiteral(strings.Repeat("public\n", 10000)) || a.reason != roles.Indeterminate {
		t.Errorf("raw body ignored deadline: reason=%q", a.reason)
	}
}

func TestAudit29RawLiteralWorkCap(t *testing.T) {
	home, work, check := audit21Fixture(t)
	var source strings.Builder
	for i := 0; i < 257; i++ {
		fmt.Fprintf(&source, "f('w%d')\n", i)
	}
	for _, scanner := range []string{"gitdir", "paths"} {
		a := &analyzer{home: home, cwd: work, protected: check, deadline: time.Now().Add(time.Second)}
		calls := 0
		a.configWriteCheck = func(name, cwd, workdir, home, xdg, global string) bool {
			calls++
			return false
		}
		a.protected = func(name, cwd string) bool {
			calls++
			return false
		}
		var denied bool
		if scanner == "gitdir" {
			denied = a.inlineGitDir(source.String(), work)
		} else {
			denied = a.interpreterProtected(source.String(), work)
		}
		if !denied || a.reason != roles.Indeterminate || calls != 0 {
			t.Errorf("%s over-budget scan: deny=%v reason=%q metadata calls=%d", scanner, denied, a.reason, calls)
		}
	}
}

func TestAudit29LiteralScannerBudgets(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, scanner := range []string{"gitdir", "paths", "executable"} {
		t.Run(scanner, func(t *testing.T) {
			now := time.Now()
			a := &analyzer{home: home, cwd: work, protected: check, deadline: now.Add(time.Second), now: func() time.Time { return now }}
			a.configWriteCheck = func(name, cwd, workdir, home, xdg, global string) bool {
				now = now.Add(2 * time.Second)
				return false
			}
			a.protected = func(name, cwd string) bool {
				now = now.Add(2 * time.Second)
				return false
			}
			var denied bool
			switch scanner {
			case "gitdir":
				denied = a.inlineGitDir("f('first'); f('second')", work)
			case "paths":
				denied = a.interpreterProtected("f('first'); f('second')", work)
			case "executable":
				denied = a.executableInterpreterProtected("f('first'); f('second')", work, "python3")
			}
			if !denied || a.reason != roles.Indeterminate {
				t.Errorf("scanner ignored deadline: deny=%v reason=%q", denied, a.reason)
			}
		})
	}
}

// Optional process-inclusive check also covers the host adapters after delayed
// stdin. Build the binary outside the repository; candidate code remains JSON.
func TestAudit29AdapterLiteralDeadline(t *testing.T) {
	binary := os.Getenv("SECRET_AUDIT29_BINARY")
	if binary == "" {
		t.Skip("set SECRET_AUDIT29_BINARY to a fresh absolute Go binary for adapter deadlines")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("SECRET_AUDIT29_BINARY must be absolute")
	}
	_, work, _ := audit21Fixture(t)
	payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": work, "tool_input": map[string]any{"command": "python3 - <<'EOF'\n" + audit29ManyLiterals() + "EOF\n"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"claude", "codex"} {
		for _, delay := range []time.Duration{0, 1900 * time.Millisecond} {
			cmd := syntheticCommand(t, binary, "hook", host)
			cmd.Dir = work
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			var output, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &stderr
			start := time.Now()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			// Only the envelope's final byte is withheld, not candidate input.
			_, writeErr := stdin.Write(payload[:len(payload)-1])
			time.Sleep(delay)
			if writeErr == nil {
				_, writeErr = stdin.Write(payload[len(payload)-1:])
			}
			stdin.Close()
			err = cmd.Wait()
			elapsed := time.Since(start)
			if err != nil || writeErr != nil || stderr.Len() != 0 {
				t.Errorf("%s delay=%s error=%v write=%v stderr=%q", host, delay, err, writeErr, stderr.String())
			}
			var decision struct {
				HookSpecificOutput struct{ PermissionDecision string }
			}
			if err := json.Unmarshal(output.Bytes(), &decision); err != nil || decision.HookSpecificOutput.PermissionDecision != "deny" {
				t.Errorf("%s delay=%s: invalid denial %q", host, delay, output.String())
			}
			if elapsed >= 2500*time.Millisecond {
				t.Errorf("%s delay=%s exceeded deadline: %s", host, delay, elapsed)
			}
			t.Logf("%s delay=%s decision=%s", host, delay, elapsed)
		}
	}
}
