package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// These prefixes exercise only transparent forms supported by unwrapCall.
var cwdFlowPrefixes = []string{
	"", "command ", "builtin ", "command builtin ", "builtin command ",
	"command -p ", "command -- ", "command -p -- ", "builtin -- ",
	"command -p builtin -- command -- ", "'command' \"builtin\" ",
}

func TestFlowCommandName(t *testing.T) {
	for _, tc := range []struct {
		source, want string
	}{
		{"cd clean", "cd"},
		{"command -p builtin -- cd clean", "cd"},
		{"VALUE=synthetic command -- builtin cd clean > output", "cd"},
		{"command builtin true", "true"},
		{"builtin -- command false", "false"},
		{"command -v cd", "command"},
		{"command -V cd", "command"},
		{"builtin -x cd", "builtin"},
		{"command -p -- cd clean", "cd"},
		{"command --", "command"},
		{"builtin", "builtin"},
		{"VALUE=synthetic", ""},
		{"$wrapper cd clean", "."},
		{"{ cd clean; }", ""},
	} {
		t.Run(tc.source, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(tc.source), "")
			if err != nil {
				t.Fatal(err)
			}
			var before, after bytes.Buffer
			if err := syntax.NewPrinter().Print(&before, file); err != nil {
				t.Fatal(err)
			}
			if got := flowCommandName(file.Stmts[0]); got != tc.want {
				t.Errorf("command name=%q want %q", got, tc.want)
			}
			if err := syntax.NewPrinter().Print(&after, file); err != nil {
				t.Fatal(err)
			}
			if before.String() != after.String() {
				t.Fatalf("flowCommandName changed AST: before=%q after=%q", before.String(), after.String())
			}
		})
	}
}

func TestCWDFlowWrappedCommands(t *testing.T) {
	root := t.TempDir()
	clean := filepath.Join(root, "clean")
	if err := os.Mkdir(clean, 0700); err != nil {
		t.Fatal(err)
	}
	// Keep expectations physical on systems whose temporary root is a symlink.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	clean = filepath.Join(root, "clean")
	for _, prefix := range cwdFlowPrefixes {
		for _, tc := range []struct {
			source           string
			success, failure []string
		}{
			{"@cd clean", []string{clean}, []string{root}},
			{"@cd missing", []string{filepath.Join(root, "missing")}, []string{root}},
			{"@pushd clean", []string{""}, []string{root}},
			{"@popd", []string{""}, []string{root}},
			{"@true", []string{root}, nil},
			{"@false", nil, []string{root}},
			{"@:", []string{root}, nil},
			{"! @cd missing", []string{root}, []string{filepath.Join(root, "missing")}},
			{"! @true", nil, []string{root}},
			{"! @false", []string{root}, nil},
			{"@cd clean && @true", []string{clean}, []string{root}},
			{"@cd clean || @false", []string{clean}, []string{root}},
			{"while @false; do cd clean; done", []string{root}, []string{root}},
		} {
			source := strings.ReplaceAll(tc.source, "@", prefix)
			t.Run(source, func(t *testing.T) {
				file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
				if err != nil {
					t.Fatal(err)
				}
				a := &analyzer{cwd: root, home: root, deadline: time.Now().Add(2 * time.Second)}
				got := a.statementFlow(file.Stmts[0], 0, []string{root})
				if a.reason != "" || !slices.Equal(got.success, tc.success) || !slices.Equal(got.failure, tc.failure) {
					t.Errorf("flow=%+v reason=%q want success=%q failure=%q", got, a.reason, tc.success, tc.failure)
				}
			})
		}
	}
}

// Audit command strings are analyzed only, never executed. All paths and file
// contents belong to this disposable synthetic fixture.
func TestCWDFlowWrappedAuditRegressions(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "clean"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", "README.md", "clean/README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", root)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", root)
	}
	cases := []struct {
		name, source string
		deny         bool
	}{
		{"failed cd semicolon", "@cd missing && make; cat .env", true},
		{"failed cd newline", "@cd missing && make\ncat .env", true},
		{"conditional cd and", "npm ci && @cd clean; cat .env", true},
		{"conditional cd or", "npm ci || @cd clean; cat .env", true},
		{"failed cd or reader", "@cd missing || cat .env", true},
		{"failed cd and reader", "@cd missing && cat .env", false},
		{"success cd and reader", "@cd clean && cat .env", false},
		{"success cd or reader", "@cd clean || cat .env", true},
		{"success cd semicolon", "@cd clean; cat .env", false},
		{"success cd newline", "@cd clean\ncat .env", false},
		{"success cd option", "@cd -- clean; cat .env", false},
		{"negated failed cd semicolon", "! @cd missing; cat .env", true},
		{"negated failed cd newline", "! @cd missing\ncat .env", true},
		{"negated failed cd and", "! @cd missing && cat .env", true},
		{"negated failed cd or", "! @cd missing || cat .env", false},
		{"negated success cd", "! @cd clean; cat .env", true},
		{"true short circuits or", "@true || cd clean; cat .env", true},
		{"false short circuits and", "@false && cd clean; cat .env", true},
		{"true and clean reader", "@true && cd clean && cat .env", false},
		{"false or clean reader", "@false || cd clean && cat .env", false},
		{"negated true", "! @true && cat .env", false},
		{"negated false", "! @false && cat .env", true},
		{"pipeline retains parent", "@cd clean | @true; cat .env", true},
		{"if failed cd", "if @true; then @cd missing; fi; cat .env", true},
		{"if conditional clean cd", "if @true; then @cd clean; fi; cat .env", true},
		{"false while retains parent", "while @false; do cd clean; done; cat .env", true},
		{"public input", "@cd missing && make; cat README.md", false},
		{"clean public input", "@cd clean; cat README.md", false},
		{"nonreader", "@cd missing && make; stat .env", false},
		{"nonreader negated", "! @cd missing; stat .env", false},
	}
	for _, prefix := range cwdFlowPrefixes {
		for _, tc := range cases {
			t.Run(prefix+tc.name, func(t *testing.T) {
				source := strings.ReplaceAll(tc.source, "@", prefix)
				if got := Analyze(source, root, root, check); (got != "") != tc.deny {
					t.Errorf("source=%q denial=%q want deny=%v", source, got, tc.deny)
				}
			})
		}
	}
}

func TestAudit15CWDSetBudget(t *testing.T) {
	root := t.TempDir()
	a := &analyzer{}
	var dirs []string
	for i := 0; i < maxWorkingDirectories; i++ {
		dirs = append(dirs, filepath.Join(root, fmt.Sprintf("dir-%d", i)))
	}
	if got := a.cwdUnion(dirs, dirs); len(got) != maxWorkingDirectories || a.reason != "" {
		t.Fatalf("dedup result=%d reason=%q", len(got), a.reason)
	}
	if got := a.cwdUnion(dirs, []string{filepath.Join(root, "extra")}); got != nil || a.reason != roles.Indeterminate {
		t.Fatalf("cwd budget not enforced: %q", a.reason)
	}
}
