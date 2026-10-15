package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// corpusCase contains only synthetic command text and metadata fixture references.
type corpusCase struct {
	Name, Command, CWD, Config, Home string
	Snapshot                         int
	Extra                            map[string]json.RawMessage
}

// deniedVariants changes literal words without making active expansions inert.
// Each replacement is independent, preserving the original shell operators.
func deniedVariants(source string) []string {
	variants := []string{source}
	seen := map[string]bool{source: true}
	add := func(start, end int, text string) {
		v := source[:start] + text + source[end:]
		if !seen[v] {
			if _, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(v), ""); err != nil {
				return
			}
			variants = append(variants, v)
			seen[v] = true
		}
	}
	if strings.ContainsRune(source, 0) {
		return variants
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		// Preserve malformed syntax rather than quote it into inert prose.
		return append(variants, "command "+source)
	}
	skip := map[*syntax.Word]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		// Declaration and time keywords are executable builtin/utility words
		// too, even though the parser does not represent them as CallExpr.
		keyword := ""
		start := 0
		switch n := node.(type) {
		case *syntax.DeclClause:
			keyword, start = n.Variant.Value, int(n.Variant.Pos().Offset())
		case *syntax.TimeClause:
			keyword, start = "time", int(n.Time.Offset())
		case *syntax.LetClause:
			keyword, start = "let", int(n.Let.Offset())
		}
		if keyword != "" {
			for _, word := range []string{"'" + keyword + "'", "\"" + keyword + "\"", "$'" + keyword + "'", "command " + keyword} {
				add(start, start+len(keyword), word)
			}
			if keyword != "time" {
				add(start, start+len(keyword), "builtin "+keyword)
			}
		}
		if r, ok := node.(*syntax.Redirect); ok && r.Hdoc != nil {
			skip[r.Word] = true
			skip[r.Hdoc] = true
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			pos := int(call.Args[0].Pos().Offset())
			add(pos, pos, "command ")
			if strings.Contains(" echo printf source . export declare typeset set read eval exec ", " "+call.Args[0].Lit()+" ") {
				add(pos, pos, "builtin ")
			}
		}
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		if skip[w] {
			return true
		}
		literalWord := true
		syntax.Walk(w, func(n syntax.Node) bool {
			switch n.(type) {
			case nil, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
			default:
				literalWord = false
			}
			return true
		})
		if !literalWord {
			return true
		}
		for _, part := range w.Parts {
			if lit, ok := part.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "*?[{}~") {
				return true
			}
		}
		value := literal(w)
		if value == "" {
			return false
		}

		start, end := int(w.Pos().Offset()), int(w.End().Offset())
		// Quote only words without active pathname/brace/tilde expansion.
		raw := source[start:end]
		if strings.ContainsAny(raw, "*?[{}~") && w.Lit() != "" {
			return false
		}
		add(start, end, "'"+strings.ReplaceAll(value, "'", "'\\''")+"'")
		double := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(value)
		add(start, end, `"`+double+`"`)
		ansi := strings.NewReplacer(`\`, `\\`, "'", `\'`, "\n", `\n`, "\t", `\t`, "\r", `\r`).Replace(value)
		add(start, end, "$'"+ansi+"'")
		if raw == value && !strings.ContainsAny(value, " \t\n'\"\\$`;|&()<>") && value != "" {
			if witness(value) {
				for i, c := range value {
					if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
						add(start, end, value[:i]+`\`+value[i:])
						// An additional alternative must not remove the protected operand.
						// Inner CSV commas are literal data, not brace alternatives.
						add(start, end, "{"+strings.ReplaceAll(value, ",", `\,`)+",}")
						break
					}
				}
			}
		}
		return false
	})
	return variants
}

// corpusEnvelope reconstructs the effective host input before validation. Replace
// only string values: malformed argv elements must retain their original types.
func corpusEnvelope(tc corpusCase, replace *strings.Replacer) (input.Envelope, error) {
	var normalize func(any) any
	normalize = func(value any) any {
		switch v := value.(type) {
		case string:
			return replace.Replace(v)
		case []any:
			for i := range v {
				v[i] = normalize(v[i])
			}
		case map[string]any:
			for key := range v {
				v[key] = normalize(v[key])
			}
		}
		return value
	}
	command, err := json.Marshal(replace.Replace(tc.Command))
	if err != nil {
		return input.Envelope{}, err
	}
	fields := map[string]json.RawMessage{"command": command}
	for key, raw := range tc.Extra {
		var value any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return input.Envelope{}, err
		}
		fields[key], err = json.Marshal(normalize(value))
		if err != nil {
			return input.Envelope{}, err
		}
	}
	data, err := json.Marshal(map[string]any{
		"tool_name": "Bash", "cwd": replace.Replace(tc.CWD), "tool_input": fields,
	})
	if err != nil {
		return input.Envelope{}, err
	}
	return input.Decode(bytes.NewReader(data))
}

type corpusDecision struct {
	command, reason string
}

// replayCorpus mirrors the host's validation, workdir and argv dispatch. Invalid
// input is an expected denial, not a failed fixture setup or a shell fragment.
func replayCorpus(t *testing.T, tc corpusCase, replace *strings.Replacer, check func(string, string) bool) []corpusDecision {
	t.Helper()
	e, err := corpusEnvelope(tc, replace)
	if err != nil {
		if !errors.Is(err, input.ErrInvalid) {
			t.Fatal(err) // Broken corpus metadata is not a policy denial.
		}
		return []corpusDecision{{reason: roles.Indeterminate}}
	}
	cwd, home := e.CWD, replace.Replace(tc.Home)
	if workdir := e.String("workdir"); workdir != "" {
		cwd = paths.Resolve(".", cwd, workdir, home)
	}
	if raw := e.Fields["command"]; len(raw) != 0 && raw[0] == '[' {
		var argv []string
		if json.Unmarshal(raw, &argv) != nil {
			return []corpusDecision{{reason: roles.Indeterminate}}
		}
		return []corpusDecision{{string(raw), AnalyzeArgv(argv, cwd, home, check)}}
	}
	var decisions []corpusDecision
	for _, variant := range deniedVariants(e.String("command")) {
		decisions = append(decisions, corpusDecision{variant, Analyze(variant, cwd, home, check)})
	}
	return decisions
}

// TestGuardDeniedCorpus evaluates generated deny cases and semantics-preserving
// literal variants against the AST policy using disposable fixture metadata.
func TestGuardDeniedCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/hook/denied-commands.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases     []corpusCase
		Snapshots [][][3]string
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	count, failures := 0, 0
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// External dependency failures are not command-text properties. The
			// Go scanner's own error/deadline tests cover that trust boundary.
			switch tc.Name {
			case "rg_find_exit", "rg_timeout", "git_grep_timeout", "rg_missing_perl_config", "rg_missing_perl", "rg_missing_find", "rg_missing_jq":
				t.Skip("Bash-only injected external dependency failure")
			}
			if strings.Contains(tc.Command, "/proc") {
				if _, err := os.Stat("/proc/self"); err != nil {
					// Without /proc (macOS, Windows) rg reads nothing there; the Bash guard allows it too.
					t.Skip("host has no /proc")
				}
			}
			tmp := t.TempDir()
			replace := strings.NewReplacer("@TMP@", filepath.ToSlash(tmp), "@ROOT@", filepath.ToSlash(root))
			for _, fixture := range corpus.Snapshots[tc.Snapshot] {
				name := filepath.Join(tmp, filepath.FromSlash(fixture[0]))
				if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
					t.Fatal(err)
				}
				switch fixture[1] {
				case "dir":
					err = os.MkdirAll(name, 0700)
				case "unreadable-dir":
					err = os.MkdirAll(name, 0000)
				case "unreadable":
					err = os.WriteFile(name, nil, 0000)
				case "link":
					err = os.Symlink(replace.Replace(fixture[2]), name)
				case "file":
					err = os.WriteFile(name, []byte(replace.Replace(fixture[2])), 0600)
				}
				if err != nil && runtime.GOOS == "windows" && strings.ContainsAny(fixture[0], "\n\r:*?\"<>|") {
					t.Skip("fixture name is not valid on Windows")
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			// Audit 14: the original scope fixture only had hidden descendants.
			// Keep these denied cases testing a visible protected file instead.
			if tc.Name == "rg_without_config_multiple" || tc.Name == "rg_without_config_glob" {
				if err := os.WriteFile(filepath.Join(tmp, "search", "sub", "app.env"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			// Audit 15 makes explicit Git worktree roots scope-sensitive.
			// Preserve real denied reads rather than the old safe-src over-denial.
			if tc.Name == "git_scope_--no-index" || tc.Name == "git_scope_--untracked" {
				if err := os.WriteFile(filepath.Join(tmp, "search", "src", "app.env"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("RIPGREP_CONFIG_PATH", replace.Replace(tc.Config))
			home := replace.Replace(tc.Home)
			check := func(name, dir string) bool {
				if !strings.Contains(name, "/") {
					if _, err := os.Lstat(paths.Resolve(name, dir, "", home)); os.IsNotExist(err) {
						return false
					}
				}
				return paths.Protected(name, dir, "", home)
			}
			for i, decision := range replayCorpus(t, tc, replace, check) {
				count++
				if decision.reason == "" {
					failures++
					if failures <= 80 {
						t.Errorf("variant %d allowed: %s", i, strconv.Quote(decision.command))
					} else {
						t.Fail()
					}
				}
			}
		})
	}
	t.Logf("%d variants from %d Bash-deny cases, %d allows", count, len(corpus.Cases), failures)
}

// TestCorpusReplay covers host overrides without running inspected commands.
func TestCorpusReplay(t *testing.T) {
	tmp := t.TempDir()
	for _, dir := range []string{"base", "target"} {
		if err := os.MkdirAll(filepath.Join(tmp, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "target", ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	replace := strings.NewReplacer("@TMP@", filepath.ToSlash(tmp), "@ROOT@", filepath.ToSlash(tmp))
	home := filepath.Join(tmp, "home")
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, tc := range []struct {
		name, command, extra string
		deny, invalid        bool
	}{
		{"base has no store", "cat .env", `{}`, false, false},
		{"absolute workdir", "cat .env", `{"workdir":"@TMP@/target"}`, true, false},
		{"relative workdir", "cat .env", `{"workdir":"../target"}`, true, false},
		{"absolute argv workdir", "ignored", `{"workdir":"@TMP@/target","command":["cat",".env"]}`, true, false},
		{"relative argv workdir", "ignored", `{"workdir":"../target","command":["cat",".env"]}`, true, false},
		{"normalized argv operand", "ignored", `{"command":["cat","@TMP@/target/.env"]}`, true, false},
		{"safe argv override", "cat @TMP@/target/.env", `{"command":["cat","src/a.go"]}`, false, false},
		{"literal shell-looking argv", "ignored", `{"workdir":"../target","command":["printf","%s","$(cat .env); cat .env"]}`, false, false},
		{"explicit shell argv", "ignored", `{"workdir":"../target","command":["bash","-c","cat .env"]}`, true, false},
		{"malformed argv", "ignored", `{"command":["cat",1]}`, true, true},
		{"malformed workdir", "true", `{"workdir":1}`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := corpusCase{Command: tc.command, CWD: "@TMP@/base", Home: "@TMP@/home"}
			if err := json.Unmarshal([]byte(tc.extra), &c.Extra); err != nil {
				t.Fatal(err)
			}
			_, err := corpusEnvelope(c, replace)
			if (err != nil) != tc.invalid || tc.invalid && !errors.Is(err, input.ErrInvalid) {
				t.Fatalf("decode error = %v, want invalid = %v", err, tc.invalid)
			}
			decisions := replayCorpus(t, c, replace, check)
			if len(decisions) == 0 {
				t.Fatal("no replay decisions")
			}
			if strings.Contains(tc.extra, `"command":[`) && len(decisions) != 1 {
				t.Fatalf("argv was expanded into %d shell variants", len(decisions))
			}
			for _, decision := range decisions {
				if (decision.reason != "") != tc.deny {
					t.Errorf("command %q reason = %q, want deny = %v", decision.command, decision.reason, tc.deny)
				}
			}
		})
	}
}

func TestCorpusEnvelopePreservesTypes(t *testing.T) {
	tmp := filepath.ToSlash(t.TempDir())
	tc := corpusCase{Command: "true", CWD: "@TMP@", Extra: map[string]json.RawMessage{
		"metadata": json.RawMessage(`{"strings":["@TMP@/one","@ROOT@/two"],"number":9007199254740993,"bool":true,"nil":null}`),
	}}
	e, err := corpusEnvelope(tc, strings.NewReplacer("@TMP@", tmp, "@ROOT@", tmp+"/root"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"bool":true,"nil":null,"number":9007199254740993,"strings":["` + tmp + `/one","` + tmp + `/root/two"]}`
	if got := string(e.Fields["metadata"]); got != want {
		t.Fatalf("metadata = %s, want %s", got, want)
	}
}

func TestDeniedVariantsRoles(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		want         []string
	}{
		{"literal operands", "cat .env", []string{
			"cat .env", "command cat .env", "'cat' .env", `"cat" .env`, "$'cat' .env",
			"cat '.env'", `cat ".env"`, "cat $'.env'", `cat .\env`, "cat {.env,}",
		}},
		{"heredoc roles", "cat <<'EOF'\ncat .env\nEOF\n", []string{
			"cat <<'EOF'\ncat .env\nEOF\n", "command cat <<'EOF'\ncat .env\nEOF\n",
			"'cat' <<'EOF'\ncat .env\nEOF\n", "\"cat\" <<'EOF'\ncat .env\nEOF\n", "$'cat' <<'EOF'\ncat .env\nEOF\n",
		}},
		{"active expansion", "cat \"$STORE\"", []string{
			"cat \"$STORE\"", "command cat \"$STORE\"", "'cat' \"$STORE\"", "\"cat\" \"$STORE\"", "$'cat' \"$STORE\"",
		}},
		{"active glob", "cat .env*", []string{
			"cat .env*", "command cat .env*", "'cat' .env*", `"cat" .env*`, "$'cat' .env*",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := deniedVariants(tc.source); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("variants = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// expandedLiteralArgv uses only the AST expander. No subprocess or command
// substitution callback is available, and pathname globbing is disabled.
func expandedLiteralArgv(t *testing.T, source string) []string {
	t.Helper()
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Stmts) != 1 {
		t.Fatalf("not one simple command: %q", source)
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		t.Fatalf("not a simple command: %q", source)
	}
	cfg := &expand.Config{}
	var words []*syntax.Word
	for _, word := range call.Args {
		syntax.SplitBraces(word)
		for expanded, err := range expand.BracesSeq(cfg, word) {
			if err != nil {
				t.Fatal(err)
			}
			// BracesSeq retains empty AST alternatives. Bash removes the
			// unquoted ones before argv formation, but preserves quoted empties.
			unquotedEmpty := true
			for _, part := range expanded.Parts {
				if lit, ok := part.(*syntax.Lit); !ok || lit.Value != "" {
					unquotedEmpty = false
					break
				}
			}
			if !unquotedEmpty {
				words = append(words, expanded)
			}
		}
	}
	argv, err := expand.Fields(cfg, words...)
	if err != nil {
		t.Fatal(err)
	}
	return argv
}

func TestDeniedVariantsCSVExpansion(t *testing.T) {
	const source = "docker run --mount type=bind,src=.env,dst=/x img cat /x"
	const preserved = `docker run --mount {type=bind\,src=.env\,dst=/x,} img cat /x`
	const splitCSV = "docker run --mount {type=bind,src=.env,dst=/x,} img cat /x"
	variants := deniedVariants(source)
	if !slices.Contains(variants, preserved) || slices.Contains(variants, splitCSV) {
		t.Fatalf("CSV alternatives not preserved: %#v", variants)
	}
	want := []string{"docker", "run", "--mount", "type=bind,src=.env,dst=/x", "img", "cat", "/x"}
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", cwd) }
	for _, variant := range variants {
		got := expandedLiteralArgv(t, variant)
		if len(got) > 0 && got[0] == "command" {
			got = got[1:]
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("variant %q argv = %#v, want %#v", variant, got, want)
		}
		if reason := Analyze(variant, cwd, cwd, check); reason == "" {
			t.Errorf("protected CSV mount variant allowed: %q", variant)
		}
	}
}

// TestDeniedVariantsCSVSplitFieldsAllow classifies the former generated spelling:
// brace expansion splits CSV fields, so --mount never receives the bind source.
func TestDeniedVariantsCSVSplitFieldsAllow(t *testing.T) {
	const splitCSV = "docker run --mount {type=bind,src=.env,dst=/x,} img cat /x"
	wantSplit := []string{"docker", "run", "--mount", "type=bind", "src=.env", "dst=/x", "img", "cat", "/x"}
	if got := expandedLiteralArgv(t, splitCSV); !reflect.DeepEqual(got, wantSplit) {
		t.Fatalf("split CSV argv = %#v, want %#v", got, wantSplit)
	}
	cwd := t.TempDir()
	if err := os.WriteFile(filepath.Join(cwd, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", cwd) }
	if got := Analyze(splitCSV, cwd, cwd, check); got != "" {
		t.Errorf("changed-argv allow regression denied: %q", got)
	}
}

// TestAudit2DeniedVariants keeps the second audit on the same literal-variant
// generator as the retained Bash corpus. Git root markers suffice here: actual
// synthetic commits and deleted-history boundaries run in hook/audit_test.go.
func TestAudit2DeniedVariants(t *testing.T) {
	data, err := os.ReadFile("../testdata/audit2.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Fixtures [][3]string
		Cases    []struct {
			Name, Tool, CWD string
			Deny            bool
			Fields          map[string]string
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, entry := range corpus.Fixtures {
		name := filepath.Join(dir, filepath.FromSlash(entry[0]))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		switch entry[1] {
		case "dir":
			err = os.MkdirAll(name, 0700)
		case "file":
			err = os.WriteFile(name, nil, 0600)
		case "link":
			err = os.Symlink(filepath.FromSlash(entry[2]), name)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, repo := range []string{"r", "r2"} {
		if err := os.MkdirAll(filepath.Join(dir, "w", repo, ".git"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	count := 0
	for _, tc := range corpus.Cases {
		if tc.Tool != "Bash" || !tc.Deny {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			source := strings.ReplaceAll(tc.Fields["command"], "@TMP@", filepath.ToSlash(dir))
			cwd := filepath.Join(dir, "w", filepath.FromSlash(tc.CWD))
			check := func(name, cwd string) bool {
				if !strings.Contains(name, "/") {
					if _, err := os.Lstat(paths.Resolve(name, cwd, "", dir)); os.IsNotExist(err) {
						return false
					}
				}
				return paths.Protected(name, cwd, "", dir)
			}
			for _, variant := range deniedVariants(source) {
				count++
				if reason := Analyze(variant, cwd, dir, check); reason == "" {
					t.Errorf("allowed audit2 variant %q", variant)
				}
			}
		})
	}
	t.Logf("checked %d audit2 denied variants", count)
}
