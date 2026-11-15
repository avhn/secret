package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// Synthetic command text only: never execute the classified Git operations.
func TestGitNoPagerListing(t *testing.T) {
	for _, protected := range []bool{false, true} {
		root := t.TempDir()
		if protected {
			if err := os.WriteFile(filepath.Join(root, ".env"), []byte("TOKEN=synthetic-only\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
		reason := Analyze("git -P ls-files -o . | xargs cat", root, root, check)
		if (reason != "") != protected {
			t.Fatalf("protected=%v, reason=%q", protected, reason)
		}
	}
}

func TestGitGlobalOptions(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GUARD_GIT_TEST", "auto")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	options := []string{
		"-C /repo", "-C/repo", "-c color.ui=auto", "-ccolor.ui=auto",
		"--git-dir /repo/.git", "--git-dir=/repo/.git", "--work-tree /repo", "--work-tree=/repo",
		"--namespace audit", "--namespace=audit", "--exec-path /repo/bin", "--exec-path=/repo/bin",
		"--config-env color.ui=GUARD_GIT_TEST", "--config-env=color.ui=GUARD_GIT_TEST",
		"--super-prefix audit/", "--super-prefix=audit/", "--attr-source HEAD", "--attr-source=HEAD",
		"--list-cmds builtins", "--list-cmds=builtins", "-p", "--paginate", "-P", "--no-pager",
		"--bare", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs",
		"--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks", "--no-lazy-fetch",
	}
	for _, option := range options {
		for _, operation := range []string{"credential fill", "credential-osxkeychain get", "config --list", "show HEAD:.env", "grep token -- .env", "apply patch.diff", "status"} {
			source := "git " + option + " " + operation
			t.Run(source, func(t *testing.T) {
				// Alternate executable lookup remains deliberately uncertifiable in Go.
				deny := operation != "status" || strings.HasPrefix(option, "--exec-path")
				reason := Analyze(source, root, root, check)
				if (reason != "") != deny {
					t.Fatalf("deny=%v, reason=%q", deny, reason)
				}
			})
		}
	}
}
