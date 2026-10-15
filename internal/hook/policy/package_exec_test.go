package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// Package commands are analyzed only. No package manager or child is executed.
func TestPackageExecScopes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"home", "web", "packages/app", "src"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", "web/.env.production", "packages/app/.env.production", "src/a.ts", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, tc := range []struct {
		argv []string
		deny bool
	}{
		{[]string{"pnpm", "-c", "exec", "cat .env"}, true},
		{[]string{"pnpm", "--shell-mode", "printenv", "TOKEN"}, true},
		{[]string{"pnpm", "-c", "printenv", "TOKEN"}, true},
		{[]string{"pnpm", "-c", "cat .env"}, true},
		{[]string{"pnpm", "-c", "tsc", "--noEmit"}, false},
		{[]string{"pnpm", "-c", "exec", "cat", ".env"}, true},
		{[]string{"pnpm", "--shell-mode", "exec", "cat .env"}, true},
		{[]string{"pnpm", "exec", "--shell-mode", "cat .env"}, true},
		{[]string{"pnpm", "exec", "-c", "cat", ".env"}, true},
		{[]string{"pnpm", "exec", "--shell-mode", "printenv TOKEN"}, true},
		{[]string{"pnpm", "exec", "--shell-mode", "echo ok; cat .env"}, true},
		{[]string{"pnpm", "exec", "--shell-mode", "echo '"}, true},
		{[]string{"pnpm", "-c", "exec", "tsc"}, false},
		{[]string{"pnpm", "exec", "--shell-mode", "tsc", "--noEmit"}, false},
		{[]string{"pnpm", "exec", "-c", "cat", "README.md"}, false},
		{[]string{"yarn", "exec", "cat", ".env"}, true},
		{[]string{"yarn", "exec", "--", "cat", ".env"}, true},
		{[]string{"yarn", "exec", "--", "tsc", "--noEmit"}, false},
		{[]string{"npm", "--workspace", "web", "exec", "cat", ".env.production"}, true},
		{[]string{"npm", "exec", "-w", "web", "cat", ".env.production"}, true},
		{[]string{"npm", "exec", "--workspace=web", "--", "cat", ".env.production"}, true},
		{[]string{"npm", "-wweb", "x", "cat", ".env.production"}, true},
		{[]string{"npm", "--prefix", "web", "exec", "cat", ".env.production"}, true},
		{[]string{"npm", "exec", "--prefix=web", "cat", ".env.production"}, true},
		{[]string{"npm", "--prefix=web", "exec", "cat", "../.env"}, true},
		{[]string{"pnpm", "-C", "web", "exec", "cat", ".env.production"}, true},
		{[]string{"pnpm", "--filter", "web", "exec", "cat", ".env.production"}, true},
		{[]string{"pnpm", "exec", "--filter=web", "cat", ".env.production"}, true},
		// Unresolved names and expressions check every possible project cwd.
		{[]string{"npm", "-w", "app", "exec", "cat", ".env.production"}, true},
		{[]string{"pnpm", "--filter", "@scope/app...", "exec", "cat", ".env.production"}, true},
		{[]string{"pnpm", "--filter", "./packages/*", "exec", "cat", ".env.production"}, true},
		{[]string{"pnpm", "--filter", "app", "-c", "exec", "cat .env.production"}, true},
		{[]string{"npm", "--workspaces", "exec", "cat", ".env.production"}, true},
		{[]string{"npm", "-w", "web", "exec", "tsc"}, false},
		{[]string{"pnpm", "--filter", "app", "exec", "tsc"}, false},
		{[]string{"pnpm", "--filter", "app", "exec", "cat", filepath.ToSlash(filepath.Join(root, "README.md"))}, false},
		{[]string{"pnpm", "--silent", "dlx", "jest", "-t", "env"}, false},
		{[]string{"npm", "-w", "web", "test"}, false},
		{[]string{"npm", "run", "lint", "--loglevel", "env"}, false},
		{[]string{"npm", "--workspace", "web", "run", "lint", "--", "env"}, false},
		{[]string{"npm", "run-script", "lint", "--", "printenv"}, false},
		{[]string{"npm", "--workspace", "web", "run", "env", "--silent"}, true},
		{[]string{"npm", "run", "printenv"}, true},
		{[]string{"npm", "run", "cat", ".env"}, true},
		// npm owns its options until --; pnpm stops at the executable.
		{[]string{"npm", "exec", "jest", "--workspace", "web", "-t", "env"}, false},
		{[]string{"npm", "exec", "--", "cat", "config.txt", "--workspace=web"}, false},
		{[]string{"pnpm", "exec", "jest", "--filter", "app", "-t", "env"}, false},
	} {
		source := make([]string, len(tc.argv))
		for i, arg := range tc.argv {
			source[i] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
		}
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			if got := Analyze(strings.Join(source, " "), root, home, check); (got != "") != tc.deny {
				t.Errorf("shell denial=%q want deny=%v", got, tc.deny)
			}
			if got := AnalyzeArgv(tc.argv, root, home, check); (got != "") != tc.deny {
				t.Errorf("argv denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
	for _, source := range []string{
		`npm -w web exec true; cat config.txt`,
		`pnpm --filter app exec true; cat config.txt`,
		`pnpm --filter web -c exec 'cd ../src'; cat config.txt`,
		`npm --prefix web exec true; cat config.txt`,
	} {
		if got := Analyze(source, root, home, check); got != "" {
			t.Errorf("child cwd escaped to sibling %q: %s", source, got)
		}
	}

	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	for _, dir := range []string{"web", "packages/app"} {
		if err := os.Symlink(".env.production", filepath.Join(root, dir, "config.txt")); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{
		`npm --workspace web exec cat config.txt`,
		`npm exec cat config.txt --workspace=web`,
		`npm exec cat config.txt --workspace web`,
		`npm exec cat config.txt -wweb`,
		`npm exec cat config.txt --prefix=web`,
		`npm exec cat config.txt --workspace web -- --child-option`,
		`pnpm --filter web cat config.txt`,
		`npm --workspace=web exec cat config.txt`,
		`npm exec -w web cat config.txt`,
		`npm exec -wweb -- cat config.txt`,
		`npm -w src -w web exec cat config.txt`,
		`npm --prefix=web exec cat config.txt`,
		`pnpm --filter web exec cat config.txt`,
		`pnpm -F web exec cat config.txt`,
		`pnpm -Fweb exec cat config.txt`,
		`pnpm --filter=app exec cat config.txt`,
		`pnpm --filter=web -c exec 'cat config.txt'`,
		`pnpm -C web exec -c cat config.txt`,
	} {
		if got := Analyze(source, root, home, check); got == "" {
			t.Errorf("workspace symlink read allowed: %s", source)
		}
	}
}

func TestPackageExecWorkspaceBounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		dirs int
		deny bool
	}{
		{"bounded", 3, false},
		{"directory limit", maxWorkingDirectories + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for i := 0; i < tc.dirs; i++ {
				if err := os.MkdirAll(filepath.Join(root, strings.Repeat("a", i+1)), 0700); err != nil {
					t.Fatal(err)
				}
			}
			check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
			if got := Analyze(`pnpm --filter @scope/app exec tsc`, root, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestPackageExecAncestorWorkspace(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"packages/app", "packages/other"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"pnpm-workspace.yaml", "packages/app/.env.production"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cwd := filepath.Join(root, "packages", "other")
	check := func(name, cwd string) bool {
		if _, err := os.Lstat(paths.Resolve(name, cwd, "", root)); os.IsNotExist(err) {
			return false
		}
		return paths.Protected(name, cwd, "", root)
	}
	for _, argv := range [][]string{
		{"pnpm", "--filter", "@scope/app", "exec", "cat", ".env.production"},
		{"npm", "-w", "app", "exec", "cat", ".env.production"},
	} {
		if got := AnalyzeArgv(argv, cwd, root, check); got == "" {
			t.Errorf("ancestor workspace read allowed: %q", argv)
		}
	}
}

func TestPackageExecShellModeNotPeeled(t *testing.T) {
	for _, args := range [][]string{
		{"-c", "exec", "cat .env"},
		{"--shell-mode", "exec", "cat .env"},
		{"exec", "--shell-mode", "cat .env"},
	} {
		if child, ok := safePackageChild("pnpm", args); ok {
			t.Errorf("shell source peeled as argv: %q", child)
		}
	}
}

func TestPackageExecWorkspaceRootOption(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".aws")
	cwd := filepath.Join(root, "packages", "app")
	if err := os.MkdirAll(cwd, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pnpm-workspace.yaml", "credentials"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool {
		if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
			return false
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, flag := range []string{"-w", "--workspace-root"} {
		for _, argv := range [][]string{
			{"pnpm", flag, "exec", "cat", "./credentials"},
			{"pnpm", "exec", flag, "cat", "./credentials"},
			{"pnpm", flag, "cat", "./credentials"},
		} {
			if got := AnalyzeArgv(argv, cwd, home, check); got == "" {
				t.Errorf("workspace-root read allowed: %q", argv)
			}
			if got := Analyze(strings.Join(argv, " "), cwd, home, check); got == "" {
				t.Errorf("workspace-root shell read allowed: %q", argv)
			}
		}
	}
}
