package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
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
						add(start, end, "{"+value+",}")
						break
					}
				}
			}
		}
		return false
	})
	return variants
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
			command := replace.Replace(tc.Command)
			if raw, ok := tc.Extra["command"]; ok {
				if err := json.Unmarshal(raw, &command); err != nil {
					t.Fatal(err)
				}
			}
			cwd, home := replace.Replace(tc.CWD), replace.Replace(tc.Home)
			check := func(name, dir string) bool {
				if !strings.Contains(name, "/") {
					if _, err := os.Lstat(paths.Resolve(name, dir, "", home)); os.IsNotExist(err) {
						return false
					}
				}
				return paths.Protected(name, dir, "", home)
			}
			for i, variant := range deniedVariants(command) {
				count++
				if got := Analyze(variant, cwd, home, check); got == "" {
					failures++
					if failures <= 80 {
						t.Errorf("variant %d allowed: %s", i, strconv.Quote(variant))
					} else {
						t.Fail()
					}
				}
			}
		})
	}
	t.Logf("%d variants from %d Bash-deny cases, %d allows", count, len(corpus.Cases), failures)
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
