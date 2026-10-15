package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"mvdan.cc/sh/v3/syntax"
)

// TestSedScriptSpecialFiles keeps the sed-only device/process rule independent
// of protected-path callbacks and of the global rules for ordinary file inputs.
func TestSedScriptSpecialFiles(t *testing.T) {
	root := t.TempDir()
	check := func(string, string) bool { return false }
	files := []struct {
		name string
		deny bool
	}{
		{"/dev/stdin", true}, {"/dev/stdout", true}, {"/dev/null", true},
		{"/dev/tty", true}, {"/dev/fd/0", true}, {"/dev/synthetic", true},
		{"/proc/self/fd/0", true}, {"/proc/self/status", true}, {"/proc/version", true},
		{"ordinary.txt", false}, {"dev/stdin", false}, {"proc/self/fd/0", false},
		{filepath.ToSlash(filepath.Join(root, "ordinary.txt")), false},
	}
	for _, cmd := range []string{"r", "R", "w", "W"} {
		for _, file := range files {
			t.Run(cmd+"/"+file.name, func(t *testing.T) {
				script := cmd + " " + file.name
				scriptFile := filepath.Join(t.TempDir(), "script.sed")
				if err := os.WriteFile(scriptFile, []byte(script+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				for _, source := range []struct {
					name string
					args []string
				}{
					{"positional", []string{script}},
					{"expression_short", []string{"-e", script}},
					{"expression_long", []string{"--expression", script}},
					{"file", []string{"-f", scriptFile}},
				} {
					t.Run(source.name, func(t *testing.T) {
						argv := append([]string{"sed"}, source.args...)
						argv = append(argv, "input.txt")
						quoted := make([]string, len(argv))
						for i, arg := range argv {
							var err error
							quoted[i], err = syntax.Quote(arg, syntax.LangBash)
							if err != nil {
								t.Fatal(err)
							}
						}
						for _, result := range []struct{ name, reason string }{
							{"Analyze", Analyze(strings.Join(quoted, " "), root, root, check)},
							{"AnalyzeArgv", AnalyzeArgv(argv, root, root, check)},
						} {
							if (result.reason != "") != file.deny {
								t.Errorf("%s denial=%q, want deny=%v", result.name, result.reason, file.deny)
							}
						}
					})
				}
			})
		}
	}
	for _, argv := range [][]string{{"cat", "/dev/null"}, {"sed", "p", "/dev/null"}} {
		if got := Analyze(strings.Join(argv, " "), root, root, check); got != "" {
			t.Errorf("ordinary special-file input %v denied: %s", argv, got)
		}
		if got := AnalyzeArgv(argv, root, root, check); got != "" {
			t.Errorf("ordinary special-file argv %v denied: %s", argv, got)
		}
	}
}

// TestSedScriptFileUncertain rejects script sources that cannot be read as bounded regular files.
func TestSedScriptFileUncertain(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, ".env")
	if err := os.WriteFile(marker, []byte("SYNTHETIC MARKER\n"), 0600); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(root, "safe.sed")
	if err := os.WriteFile(safe, []byte("p\n"), 0600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(root, "large.sed")
	if err := os.WriteFile(large, []byte(strings.Repeat("#x\n", 3000)), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.sed")
	linkErr := os.Symlink(safe, link)
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, source := range []string{"-", "/dev/stdin", "/proc/self/fd/0", filepath.Join(root, "missing.sed"), root, large} {
		t.Run(source, func(t *testing.T) {
			if got := AnalyzeArgv([]string{"sed", "-f", source, "in.txt"}, root, root, check); got == "" {
				t.Fatal("uncertain sed script source allowed")
			}
		})
	}
	if linkErr == nil {
		if got := AnalyzeArgv([]string{"sed", "-f", link, "in.txt"}, root, root, check); got == "" {
			t.Fatal("symlinked script source allowed")
		}
	}
	if got := AnalyzeArgv([]string{"sed", "-f", safe, "in.txt"}, root, root, check); got != "" {
		t.Fatalf("safe regular script denied: %s", got)
	}
}
