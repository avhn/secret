package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// Function source is analyzed only, never executed. The protected alias and all
// file contents belong to this disposable synthetic fixture.
func TestFunctionScopeCWD(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"src", "web"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", "README.md", "config.txt", "src/README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(root, ".env"), filepath.Join(root, "web", "config.txt")); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool {
		return paths.Protected(name, cwd, "", root)
	}
	for _, tc := range []struct {
		name, source string
		deny         bool
	}{
		{"definition public reader", "f() { cd src; }; cat README.md", false},
		{"definition public command", "f() { cd src; }; npm test", false},
		{"definition outer alias name", "f() { cd web; }; cat config.txt", false},
		{"definition keyword parentheses", "function f() { cd web; }; cat config.txt", false},
		{"definition keyword", "function f { cd web; }; cat config.txt", false},
		{"definition nested block", "f() { { cd web; }; }; cat config.txt", false},
		{"definition keeps protected parent", "f() { cd src; }; cat .env", true},
		{"definition checks body", "f() { cat .env; }", true},
		{"definition checks alias body", "f() { cd web; cat config.txt; }", true},
		{"definition nested function", "f() { g() { cd web; }; cd src; }; cat .env", true},
		{"nested definition keeps body cwd", "f() { g() { cd web; }; cat config.txt; }", false},
		{"nested definition keeps parent cwd", "f() { g() { cd web; }; }; cat config.txt", false},
		{"invoked alias", "f() { cd web; }; f; cat config.txt", true},
		{"invoked public reader", "f() { cd src; }; f; cat README.md", false},
		{"invoked reader uses call cwd", "f() { cat config.txt; }; cd web; f", true},
		{"invoked nested block", "f() { { cd web; }; }; f; cat config.txt", true},
		{"invoked conditional cwd", "f() { if true; then cd web; fi; }; f; cat config.txt", true},
		{"invoked and", "f() { cd web; }; f && cat config.txt", true},
		{"invoked or", "f() { cd web; }; f || cat config.txt", true},
		{"invoked negated", "f() { cd web; }; ! f; cat config.txt", true},
		{"invoked background keeps parent", "f() { cd web; }; f & cat config.txt", false},
		{"invoked subshell keeps parent", "f() { cd web; }; (f); cat config.txt", false},
		{"invoked pipeline keeps parent", "f() { cd web; }; f | true; cat config.txt", false},
		{"function subshell body", "f() (cd web); f; cat config.txt", false},
		{"invoked child reader", "f() { cd web; cat config.txt; }; f &", true},
		{"invoked nested function", "f() { g() { cd web; }; g; }; f; cat config.txt", true},
		{"definition does not publish nested function", "f() { g() { cd web; }; }; g; cat config.txt", false},
		{"invoked publishes nested function", "f() { g() { cd web; }; }; f; g; cat config.txt", true},
		{"subshell definition stays local", "(f() { cd web; }); f; cat config.txt", false},
		{"subshell redefinition stays local", "f() { cd web; }; (f() { cd src; }); f; cat config.txt", true},
		{"background definition stays local", "f() { cd web; } & f; cat config.txt", false},
		{"pipeline definition stays local", "{ f() { cd web; }; } | true; f; cat config.txt", false},
		{"conditional redefinition retains earlier body", "f() { cd web; }; if false; then f() { cd src; }; fi; f; cat config.txt", true},
		{"conditional definition retains parent cwd", "if false; then f() { cd src; }; fi; f; cat .env", true},
		{"invoked quoted name", "f() { cd web; }; 'f'; cat config.txt", true},
		{"invoked escaped name", "f() { cd web; }; \\f; cat config.txt", true},
		{"invoked brace name", "f() { cd web; }; f{,}; cat config.txt", true},
		{"external path is not a function", "f() { cd web; }; ./f; cat config.txt", false},
		{"command conservative normalization", "f() { cd web; }; command f; cat config.txt", true},
		{"builtin conservative normalization", "f() { cd web; }; builtin f; cat config.txt", true},
		{"wrapped conservative normalization", "f() { cd web; }; command -p builtin -- f; cat config.txt", true},
		{"direct recursion bounded", "f() { f; }; f; cat config.txt", true},
		{"mutual recursion bounded", "f() { g; }; g() { f; }; f; cat config.txt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze(tc.source, root, root, check); (got != "") != tc.deny {
				t.Errorf("source=%q denial=%q want deny=%v", tc.source, got, tc.deny)
			}
		})
	}
}

func TestFunctionScopeBounds(t *testing.T) {
	var directories strings.Builder
	for i := 0; i < maxWorkingDirectories; i++ {
		fmt.Fprintf(&directories, "f() { cd dir%d; }; ", i)
	}
	directories.WriteString("f")
	var steps strings.Builder
	const bodySteps = 32
	steps.WriteString("f() { ")
	steps.WriteString(strings.Repeat(":;", bodySteps))
	steps.WriteString(" }; ")
	for i := 0; i < maxFlowSteps/bodySteps+1; i++ {
		steps.WriteString("f;")
	}
	root := t.TempDir()
	for _, tc := range []struct{ name, source string }{
		{"direct recursion", "f() { f; }; f"},
		{"mutual recursion", "f() { g; }; g() { f; }; f"},
		{"directory alternatives", directories.String()},
		{"flow steps", steps.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(string, string) bool { return false }
			if got := Analyze(tc.source, root, root, check); got != roles.Indeterminate {
				t.Errorf("denial=%q want %q", got, roles.Indeterminate)
			}
		})
	}
}
