package policy

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

func TestAudit27GitDirectoryDestinations(t *testing.T) {
	home, work, check := audit21Fixture(t)
	t.Setenv("GIT_CONFIG_GLOBAL", "")
	xdg := filepath.Join(filepath.Dir(home), "xdg")
	gitdir := filepath.Join(filepath.Dir(home), "gitdir")
	for _, dir := range []string{filepath.Join(home, ".config", "git"), filepath.Join(xdg, "git"), gitdir, filepath.Join(work, "tpl"), filepath.Join(work, "public")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{
		filepath.Join(work, ".git"):          "gitdir: " + filepath.ToSlash(gitdir) + "\n",
		filepath.Join(gitdir, "HEAD"):        "ref: refs/heads/synthetic\n",
		filepath.Join(work, "tpl", "config"): "synthetic\n",
	} {
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, custom := range []bool{false, true} {
		t.Setenv("XDG_CONFIG_HOME", "")
		destinations := []string{"~/.config/git/", shellLiteral(filepath.ToSlash(gitdir) + "/")}
		if custom {
			t.Setenv("XDG_CONFIG_HOME", xdg)
			destinations = append(destinations, "$XDG_CONFIG_HOME/git/", "${XDG_CONFIG_HOME}/git/")
		}
		for _, destination := range destinations {
			for _, source := range []string{
				"cp tpl/config " + destination,
				"mv tpl/config " + destination,
				"install -m 644 -t " + destination + " tpl/config",
				"ln -s tpl/config " + destination,
				"cd " + destination + " && cp " + shellLiteral(filepath.ToSlash(filepath.Join(work, "tpl", "config"))) + " .",
			} {
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("allowed Git directory destination: %s", source)
				}
			}
		}
	}
	for _, source := range []string{"cp tpl/config public/", "mv tpl/config public/", "install -m 644 -t public tpl/config", "ln -s tpl/config public/", "cat ~/.config/git/config"} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("safe directory control %s: %s", source, reason)
		}
	}
}

func TestAudit27AssignmentSubstitutions(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`a=("$(cat .env)"); printf '%s\n' "${a[@]}"`,
		`a=($(cat .env))`,
		"a=(`cat .env`)",
		`a+=("$(cat .env)")`,
		`a=([0]="$(cat .env)")`,
		`a=([$(cat .env)]=public)`,
		`a[$(cat .env)]=public`,
		`a[$(cat .env)]+=public`,
		`a=(<(cat .env))`,
		`a=(>(cat .env))`,
		`a[$(cat .env)]=public true`,
		`declare -a a=("$(cat .env)")`,
		`(a=("$(cat .env)"))`,
		`{ a=("$(cat .env)"); }`,
		`bash -c 'a=("$(cat .env)")'`,
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed active assignment substitution: %s", source)
		}
	}
	for _, source := range []string{
		`a=("$(cat README.md)")`,
		`a=([$(cat README.md)]=public)`,
		`a[$(cat README.md)]=public`,
		`a=(<(cat README.md))`,
		`a=('$(cat .env)' 'public')`,
		`a=('` + "`cat .env`" + `')`,
		`a=(public 'two words')`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert assignment control %s: %s", source, reason)
		}
	}
}

func TestAudit27CommandFieldSplitting(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, variable := range []string{"IFS", "SEP"} {
		for _, delimiter := range []string{" ", "\t", " \t "} {
			for _, reader := range []string{"cat", "head", "tail"} {
				for _, prefix := range []string{"", "command ", "env "} {
					source := variable + "=" + shellLiteral(delimiter) + "; " + prefix + reader + "${" + variable + "}.env"
					if reason := Analyze(source, work, home, check); reason == "" {
						t.Errorf("allowed split reader: %s", source)
					}
				}
			}
		}
	}
	for _, source := range []string{
		`SEP=' '; cat${SEP}README.md`,
		`SEP=' '; command cat${SEP}README.md`,
		`SEP=' '; "cat${SEP}.env"`,
		`SEP=' '; printf '%s' "cat${SEP}.env"`,
		`IFS=' '; true`,
		`SEP=' '; echo a${SEP}b`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("field splitting control %s: %s", source, reason)
		}
	}
}

func TestAudit27IFSState(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`IFS=''; echo $HOME`,
		`IFS=''; s='hello world'; echo $s`,
		`IFS=; s='hello world'; echo $s`,
		`IFS=""; s='hello world'; echo $s`,
		`echo $HOME # IFS`,
		`printf IFS; echo $HOME`,
		`printf 'IFS=:'; echo $HOME`,
		`echo 'read IFS'; echo $HOME`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("inert or disabled IFS control %s: %s", source, reason)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason != "" {
			t.Errorf("argv inert or disabled IFS control %s: %s", source, reason)
		}
	}
	for _, source := range []string{
		`IFS=$UNKNOWN; echo $HOME`,
		`IFS=''; IFS=$UNKNOWN; echo $HOME`,
		`IFS=''; IFS=':'; echo $HOME`,
		`IFS=''; IFS=$UNKNOWN; SEP='cat .env'; $SEP`,
		`IFS=''; read IFS; SEP='cat .env'; $SEP`,
		`IFS=''; IFS[0]=$UNKNOWN; SEP='cat .env'; $SEP`,
		`IFS=''; name=IFS; printf -v "$name" ' '; SEP='cat .env'; $SEP`,
		`IFS=''; declare -n target=IFS; target=' '; SEP='cat .env'; $SEP`,
		`read IFS; echo $HOME`,
		`unset IFS; echo $HOME`,
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed uncertified IFS state: %s", source)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
			t.Errorf("allowed argv uncertified IFS state: %s", source)
		}
	}
}

func TestAudit27EmptyIFSFields(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		assignment string
		word       string
		want       []string
	}{
		{`IFS=''`, `$SEP`, []string{"hello world"}},
		{`IFS=`, `$SEP`, []string{"hello world"}},
		{`IFS=""`, `$SEP`, []string{"hello world"}},
		{`IFS=''`, `a${IFS}b`, []string{"ab"}},
		{`IFS=''`, `"${IFS}"`, []string{""}},
		{`IFS=''`, `${IFS}`, nil},
	} {
		source := tc.assignment + "; SEP='hello world'; " + tc.word
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(tc.word), "")
		if err != nil {
			t.Fatal(err)
		}
		a := &analyzer{home: home, protected: check, source: source, ifsEmpty: true, env: map[string]string{"IFS": "", "SEP": "hello world"}, assignments: map[string]int{"IFS": 1, "SEP": 1}, deadline: time.Now().Add(2 * time.Second)}
		got, ok := a.expandWord(file.Stmts[0].Cmd.(*syntax.CallExpr).Args[0], work)
		if !ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: fields=%q, known=%v, want=%q", source, got, ok, tc.want)
		}
	}
}

func TestAudit27IFSUnknownMutations(t *testing.T) {
	for _, source := range []string{
		`read IFS`, `unset IFS`, `printf -v IFS ':'`, `printf -vIFS ':'`,
		`declare IFS`, `for IFS in ':'; do true; done`, `(( IFS++ ))`,
		`echo ${IFS:=:}`, `IFS=$UNKNOWN`,
	} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
		if err != nil {
			t.Fatal(err)
		}
		a := &analyzer{source: source}
		a.noteIFS(file, source)
		if _, ok := a.appendLiteralFields(nil, "cat .env", "cat .env", false, true); ok || a.reason == "" {
			t.Errorf("certified splitting with unknown IFS: %s", source)
		}
	}
}

func TestAudit27SplitWordFields(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		word string
		want []string
	}{
		{`cat${SEP}.env`, []string{"cat", ".env"}},
		{`${SEP}cat${SEP}`, []string{"cat"}},
		{`"cat${SEP}.env"`, []string{"cat .env"}},
		{`'cat${SEP}.env'`, []string{"cat${SEP}.env"}},
		{`cat\ .env`, []string{"cat .env"}},
		{`""${SEP}`, []string{""}},
		{`cat${SEP}""`, []string{"cat", ""}},
		{`cat${SEP}${SEP}.env`, []string{"cat", ".env"}},
		{`cat${SEP}"a b"`, []string{"cat", "a b"}},
		{`{cat,head}${SEP}.env`, []string{"cat", ".env", "head", ".env"}},
	} {
		t.Run(tc.word, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(tc.word), "")
			if err != nil {
				t.Fatal(err)
			}
			a := &analyzer{home: home, protected: check, source: "SEP=' '; " + tc.word, env: map[string]string{"SEP": " "}, assignments: map[string]int{"SEP": 1}, deadline: time.Now().Add(2 * time.Second)}
			got, ok := a.expandWord(file.Stmts[0].Cmd.(*syntax.CallExpr).Args[0], work)
			if !ok || !reflect.DeepEqual(got, tc.want) {
				t.Errorf("fields=%q, known=%v, want=%q", got, ok, tc.want)
			}
		})
	}
}

func TestAudit27FieldSplittingLimits(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`IFS=':'; SEP='cat:.env'; $SEP`,
		`IFS=':'; SEP='a:b'; echo $SEP`,
		`IFS=' '; IFS=':'; SEP='cat:.env'; $SEP`,
		"SEP=" + shellLiteral(strings.Repeat("public ", 257)) + "; echo $SEP",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("allowed uncertified or over-budget field splitting: %s", source)
		}
	}
	for _, source := range []string{`IFS=':'; SEP='public'; echo $SEP`, `IFS=':'; SEP='a:b'; echo "$SEP"`} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("non-splitting control %s: %s", source, reason)
		}
	}
}

func TestAudit27MalformedShellFraming(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`f() true`, `function f() true`, `function f true`, `f() true > out`,
		`f() ! { true; }`, `f() time true`, `f() function g() { true; }`,
		`time -p && true`, `time && true`, `time -p || true`, `time -p | true`,
		`time -p ! && true`, `time -p ! | true`,
		`time -- && true`, `time -- || true`, `time -- | true`, `time -- |& true`,
		`time -p -- && true`, `time -p -- || true`, `time -p -- | true`, `time -p -- |& true`,
		`time -- ! && true`, `time -- ! | true`, `time -p -- ! && true`, `time -p -- ! |& true`,
		`time -- time && true`, `time -- time | true`, `time -- time -p -- | true`,
	} {
		for _, wrapped := range []string{source, "( " + source + " )", "{ " + source + "; }", "true; " + source, "bash -c " + shellLiteral(source)} {
			if reason := Analyze(wrapped, work, home, check); reason == "" {
				t.Errorf("allowed malformed shell framing: %s", wrapped)
			}
		}
	}
	for _, source := range []string{
		`f() { true; }`, `function f() { true; }`, `function f { true; }`,
		`f() (true)`, `f() if true; then true; fi`, `f() [[ x ]]`, `f() (( 1 ))`,
		`f() { true; } > out`, `f() { true; } &`,
		`time`, `time -p`, `time -p true`, `time -p; true`, `true && time`,
		`time --`, `time -- true`, `time -p --`, `time -p -- true`,
		`time '--' && true`, `time "--" | true`, `time \-- && true`, `time -- -- && true`,
		`time -- !`, `time -- ! true`, `time -- ! true | true`, `time -- time true | true`,
		`time -- -- | true`, `time -- > out && true`,
		`true | time`, `true | time -p`, `time -p & true`, `time -p > out && true`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("valid framing control %s: %s", source, reason)
		}
	}
	// These Bash-valid forms already failed Go parsing before audit 27.
	// Keep that conservative decision unchanged rather than broaden this fix.
	for _, source := range []string{`time !`, `time -p ! true && true`, `a[$(cat README.md)]=public true`} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("existing conservative decision loosened: %s", source)
		}
	}
}
