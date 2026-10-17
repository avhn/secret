package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
	"mvdan.cc/sh/v3/syntax"
)

// These probes are analyzed as strings only, never executed.
func TestCorpusDeclarationAssignments(t *testing.T) {
	repo, _, root := isolatedGitFixture(t)
	t.Setenv("EDITOR", "sh") // Inherited settings remain outside command-text policy.
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, prefix := range []string{"", "command ", "builtin ", "command -p ", "command -- ", "command builtin "} {
		for _, builtin := range []string{"export", "declare", "typeset"} {
			for _, spelling := range []string{builtin, "'" + builtin + "'", `"` + builtin + `"`, "$'" + builtin + "'"} {
				for _, tc := range []struct {
					operand string
					deny    bool
				}{
					{"EDITOR=sh", true}, {"GIT_ASKPASS=vim", true},
					{"'EDITOR=sh'", true}, {`"EDITOR=sh"`, true}, {"'BASH_ENV=.env'", true},
					{"'EDITOR=code -w'", false}, {"'FOO=bar'", false},
					{"EDITOR='code -w'", false}, {"GIT_PAGER='less -FRX'", false}, {"FOO=bar", false},
					{"EDITOR+=sh", true}, {"EDITOR=$UNKNOWN", true}, {`"EDITOR=$UNKNOWN"`, true},
				} {
					source := prefix + spelling + " " + tc.operand + "; git status"
					t.Run(source, func(t *testing.T) {
						if got := Analyze(source, repo, root, check); (got != "") != tc.deny {
							t.Errorf("denial=%q want deny=%v", got, tc.deny)
						}
					})
				}
			}
		}
	}
	for _, source := range []string{
		`git status`, `printf '%s' 'EDITOR=sh'`, `echo 'GIT_ASKPASS=vim'`,
		`'export' ''; git status`,
		`'export' EDITOR=code; 'export' EDITOR+=' -w'; git status`,
	} {
		if got := Analyze(source, repo, root, check); got != "" {
			t.Errorf("safe %q denied: %s", source, got)
		}
	}
	for _, source := range []string{
		`x=vim; 'export' EDITOR=$x; git status`,
		`x=vim; 'export' "EDITOR=$x"; git status`,
		`x=vim; command declare 'EDITOR'=$x; git status`,
		`name=EDITOR; 'export' "$name=vim"; git status`,
		`name=EDITOR; command declare "$name=vim"; git status`,
		`name=EDITOR; export "$name=vim"; git status`,
		`x=vim; {'export',} EDITOR=$x; git status`,
		`x=vim; {'declare',} EDITOR=$x; git status`,
		`x=vim; {'typeset',} EDITOR=$x; git status`,
		`x=vim; {'command',} {'declare',} EDITOR=$x; git status`,
		`x=vim; {command,declare} EDITOR=$x; git status`,
		`command export CDPATH=sub; cd missing; cat .env`,
		`export 'CDPATH=sub'; cd missing; cat .env`,
	} {
		if got := Analyze(source, repo, root, check); got == "" {
			t.Errorf("nonliteral assignment allowed: %s", source)
		}
	}
	for _, argv := range [][]string{{"export", "EDITOR=sh"}, {"command", "declare", "EDITOR=sh"}, {"typeset", "GIT_ASKPASS=vim"}} {
		if got := AnalyzeArgv(argv, repo, root, check); got == "" {
			t.Errorf("assignment argv allowed: %q", argv)
		}
	}
	for _, argv := range [][]string{{"export", "EDITOR=code -w"}, {"command", "declare", "FOO=bar"}, {"typeset", "GIT_PAGER=less -FRX"}} {
		if got := AnalyzeArgv(argv, repo, root, check); got != "" {
			t.Errorf("safe argv %q denied: %s", argv, got)
		}
	}
}

func TestCorpusRedirectRecipientsAndSinks(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"linked/objects", "linked/refs"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"linked/HEAD", ".env", "notes.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, prefix := range []string{"", "command ", "command -- ", "command -p ", "command -p -- ", "builtin command ", "{'command',} "} {
		for _, recipient := range []string{"python3 -", "'python3' -", "{'python3',} -", "{,p''ython3} -", "node", `"node"`} {
			for _, tc := range []struct {
				body string
				deny bool
			}{
				{`open("linked/config","w")`, true},
				{`require("fs").writeFileSync("linked/hooks/post-checkout","x")`, true},
				{`print(1)`, false},
			} {
				for _, redirection := range []string{" <<'EOF'\n" + tc.body + "\nEOF", " <<<'" + tc.body + "'"} {
					source := prefix + recipient + redirection
					if got := Analyze(source, root, root, check); (got != "") != tc.deny {
						t.Errorf("%q denial=%q want deny=%v", source, got, tc.deny)
					}
				}
			}
		}
		for _, sink := range []string{"cat > ", "tee "} {
			for _, tc := range []struct {
				target string
				deny   bool
			}{
				{"{.env,}", true}, {"{'.env',}", true}, {".env", true},
				{"{notes.md,}", false}, {"{'notes.md',}", false}, {"notes.md", false},
			} {
				for _, redirection := range []string{" <<'EOF'\n.env\nEOF", " <<<'.env'"} {
					source := prefix + sink + tc.target + redirection
					if got := Analyze(source, root, root, check); (got != "") != tc.deny {
						t.Errorf("%q denial=%q want deny=%v", source, got, tc.deny)
					}
				}
			}
		}
		for _, source := range []string{
			`cat > notes.md <<<'open("linked/config","w")'`,
			`tee notes.md <<<'open("linked/config","w")'`,
			"git commit -F - <<'EOF'\nopen(\"linked/config\",\"w\") is prose\nEOF",
			`cat > .env <<<'ordinary data'`,
			`command -v python3 <<<'open("linked/config","w")'`,
		} {
			if got := Analyze(prefix+source, root, root, check); got != "" {
				t.Errorf("safe %q denied: %s", prefix+source, got)
			}
		}
	}
}

func TestCorpusDockerMountBraces(t *testing.T) {
	root := t.TempDir()
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`docker run --mount {'type=bind,src=.env,dst=/x',} img cat /x`, true},
		{`docker run --mount {"type=bind,src=.env,dst=/x",} img cat /x`, true},
		{`docker run --mount {type=bind\,src=.env\,dst=/x,} img cat /x`, true},
		{`docker run --mount {'type=bind,src=notes.md,dst=/x',} img cat /x`, false},
		{`docker run --mount type=bind,src=notes.md,dst=/x img cat /x`, false},
		{`docker {,i''nspect} "$UNKNOWN"`, true},
		{`docker run {--mount,} "$UNKNOWN" img cat /x`, true},
		// The empty alternative retains the '--' prefix, so --mount receives
		// a literal '--' value, not the unresolved following argument.
		{`docker run --{mount,} "$UNKNOWN" img cat /x`, false},
		{`docker run {--volume,} "$UNKNOWN" img cat /x`, true},
		{`docker run {-v,} "$UNKNOWN" img cat /x`, true},
		{`docker run {--mount,} type=bind,src=notes.md,dst=/x --label "$UNKNOWN" img`, false},
		{`docker run --mount "$UNKNOWN" img cat /x`, true},
		{`docker run --volume "$UNKNOWN" img cat /x`, true},
		{`docker run -v"$UNKNOWN" img cat /x`, true},
		{`docker run --label "$UNKNOWN" img`, false},
		{`docker run --label "--mount=$UNKNOWN" img`, false},
		{`docker run --label "-version=$UNKNOWN" img`, false},
		{`docker run --env "--volume=$UNKNOWN" img`, false},
		{`docker run --env-file "-v$UNKNOWN" img`, false},
		{`docker run --label "$UNKNOWN" --mount "$OTHER" img`, true},
		{`docker run img printf '%s' "--mount=$UNKNOWN"`, false},
		{`docker run --env-file "$UNKNOWN" img`, false},
		{`docker run --mount type=bind,src=notes.md,dst=/x --label "$UNKNOWN" img`, false},
		{`docker run --volume notes.md:/x --env-file "$UNKNOWN" img`, false},
		{`docker run -v $PWD:/src img`, false},
		{`docker run -v ${PWD}:/src img`, false},
		{`docker run -v $(pwd):/src img`, false},
		{`docker run -v "$(pwd):/src" img`, false},
		{`docker run -v "$(pwd)":/src img`, false},
		{`docker run -v$PWD:/src img`, false},
		{`docker run --volume=${PWD}:/src img`, false},
		{`PWD=$UNKNOWN; docker run -v $PWD:/src img`, true},
		{`docker run -v $(printf .env):/src img`, true},
	} {
		if got := Analyze(tc.source, root, root, check); (got != "") != tc.deny {
			t.Errorf("%q denial=%q want deny=%v", tc.source, got, tc.deny)
		}
	}
}

func TestCorpusBraceFieldProvenance(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		word string
		want []string
	}{
		{`{,i''nspect}`, []string{"inspect"}},
		{`{,i""nspect}`, []string{"inspect"}},
		{`{'',inspect}`, []string{"", "inspect"}},
		{`{'a,b',}`, []string{"a,b"}},
		{`{"",}`, []string{""}},
		{`{,}''`, []string{"", ""}},
		{`{a,b}{,}`, []string{"a", "a", "b", "b"}},
		{`pre{,x}`, []string{"pre", "prex"}},
		{`{a,}"suffix"`, []string{"asuffix", "suffix"}},
		{`{,}`, nil},
		{`--{mount,}`, []string{"--mount", "--"}},
	} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader("printf %s "+tc.word), "")
		if err != nil {
			t.Fatal(err)
		}
		call := file.Stmts[0].Cmd.(*syntax.CallExpr)
		a := &analyzer{deadline: time.Now().Add(2 * time.Second)}
		got, ok := a.expandWord(call.Args[2], root)
		if !ok || !slices.Equal(got, tc.want) {
			t.Errorf("%s fields=%q known=%v want=%q", tc.word, got, ok, tc.want)
		}
	}
	for _, word := range []string{`{1..3}`, strings.Repeat("{a,b}", 7)} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader("echo "+word), "")
		if err != nil {
			t.Fatal(err)
		}
		call := file.Stmts[0].Cmd.(*syntax.CallExpr)
		a := &analyzer{deadline: time.Now().Add(2 * time.Second)}
		if fields, known := a.expandWord(call.Args[1], root); known {
			t.Errorf("unsupported expansion %s certified as %q", word, fields)
		}
	}
}
