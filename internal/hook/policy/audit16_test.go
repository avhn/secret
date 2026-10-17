package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// All commands are analyzer input only. Fixtures and HOME are synthetic.
func TestAudit16(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"src", "public", "a", "other/.secrets"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", ".env.ts", "README.md", "a/README.md", "src/a.ts", "public/a.ts", "other/.env", "other/.env.local", "other/.secrets/a.ts"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		name, source, dir string
		deny              bool
	}{
		{"A1 rg negative", "rg --hidden -g '!*.md' KEY", "", true},
		{"A1 rg negative braces", "rg -g '{*.ts,!*.md}' KEY", "", true},
		{"A1 rg public", "rg -g '*.ts' KEY public", "", false},
		{"A2 rg negated class", "rg -g '[!_]*.ts' KEY", "", true},
		{"A2 find negated class", "find . -name '[!_]*.ts' | xargs cat", "", true},
		{"A2 public class", "rg -g '[!_]*.ts' KEY public", "", false},
		{"A4 fd boolean flag", "fd -H -g -x cat .env", "", true},
		{"A4 fd pattern", "fd -g -H '.env*' -x cat", "", true},
		{"A4 fd long glob", "fd --glob -H '*.env' -X cat", "", true},
		{"A4 fd public glob", "fd -g -H '*.ts' public -x cat", "", false},
		{"A4 fd names", "fd -g -H '.env*'", "", false},
		{"A5 fd positional root", "fd -e local . ../other -x cat", "public", true},
		{"A5 fd search path", "fd -e ts --search-path ../other -x cat", "public", true},
		{"A5 fd base directory", "fd -e ts --base-directory ../other -x cat", "public", true},
		{"A5 fd pipe root", "fd -H . ../other | xargs cat", "public", true},
		{"A5 fd pipe search path", "fd -H . --search-path ../other | xargs cat", "public", true},
		{"A5 fd public root", "fd -e ts . ../public -x cat", "public", false},
		{"A5 fd public pipe", "fd -g '*.ts' ../public | xargs cat", "public", false},
		{"A5 fd empty pattern", "fd -H '' ../other | xargs cat", "public", true},
		{"A5 fd base pipe", "fd --base-directory=../other . | xargs cat", "public", true},
		{"A5 fd public unfiltered pipe", "fd -H . ../public | xargs cat", "public", false},
		{"A5 fd metadata", "fd -H . ../other -x stat", "public", false},
		{"A7 npm x", "npm x dotenvx -- get", "", true},
		{"A7 npm x public", "npm x jest -- -t env", "", false},
		{"A7 npm x package", "npm x --package=dotenvx -- dotenvx get", "", true},
		{"A7 npm exec package", "npm exec -p jest jest -k env", "", false},
		{"A7 npm x package public", "npm x --yes --package vitest vitest run env", "", false},
		{"B2 pytest", "python3 -m pytest -k env", "", false},
		{"B2 python pytest", "python -m pytest -k env", "", false},
		{"B2 dotenv", "python3 -m dotenv get KEY", "", true},
		{"B3 attached type", "rg -tts export", "public", false},
		{"B3 attached exclusion", "rg -Tts KEY .env", "", true},
		{"B3 attached exclusion public", "rg -Tts KEY public", "", false},
		{"B3 attached type protected", "rg --hidden -tts KEY other", "", true},
		{"B5 quiet", "rg -q KEY .env", "", false},
		{"B5 quiet long", "rg --quiet KEY .env", "", false},
		{"B5 content", "rg KEY .env", "", true},
		{"B5 quiet pattern input", "rg -q -f .env src/a.ts", "", true},
		{"B6 narrowed directory", "rg -g 'src/**' export", "", false},
		{"B6 protected directory", "rg -g 'other/**' KEY", "", true},
		{"B7 block", "{ cd a && make; }; cat README.md", "", false},
		{"B7 if", "if [ -d a ]; then cd a; fi; npm test", "", false},
		{"B7 block retained cwd", "{ cd a && make; }; cat .env", "", true},
		{"B7 if retained cwd", "if [ -d a ]; then cd a; fi; cat .env", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := filepath.Join(root, tc.dir)
			if got := Analyze(tc.source, cwd, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestAudit16RGIgnoreOverrides(t *testing.T) {
	for _, location := range []string{".", "src", "src/nested"} {
		for _, ignore := range []string{".ignore", ".rgignore"} {
			t.Run(location+"/"+ignore, func(t *testing.T) {
				root := t.TempDir()
				if err := os.MkdirAll(filepath.Join(root, "src", "nested"), 0700); err != nil {
					t.Fatal(err)
				}
				for name, data := range map[string]string{".gitignore": "app.env\n", "src/.gitignore": "app.env\n", "src/app.env": "synthetic\n"} {
					if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				syntheticRepo(t, root, 2)
				t.Setenv("RIPGREP_CONFIG_PATH", "")
				check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
				if got := Analyze("rg KEY", filepath.Join(root, "src"), root, check); got != "" {
					t.Fatalf("plain ignored file denied: %s", got)
				}
				if err := os.WriteFile(filepath.Join(root, location, ignore), []byte("!app.env\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if got := Analyze("rg KEY", filepath.Join(root, "src"), root, check); got == "" {
					t.Fatal("rg ignore override certified an ignored credential")
				}
			})
		}
	}
}

func TestAudit16FilteredFindSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	root := t.TempDir()
	public := filepath.Join(root, "public.ts")
	protected := filepath.Join(root, ".env")
	for _, name := range []string{public, protected} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		name, target string
		deny         bool
	}{{"public", public, false}, {"protected", protected, true}, {"directory", root, true}} {
		dir := filepath.Join(root, tc.name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(tc.target, filepath.Join(dir, "selected.ts")); err != nil {
			t.Fatal(err)
		}
		for _, flag := range []string{"-L", "-H"} {
			source := "find " + flag + " " + tc.name + " -name '*.ts' | xargs cat"
			if got := Analyze(source, root, root, check); (got != "") != tc.deny {
				t.Errorf("%s: denial=%q want deny=%v", source, got, tc.deny)
			}
		}
	}
}

func TestAudit16NegativeRGDefaultScope(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, source := range []string{"rg -g '!.env' KEY", "rg --glob='!*.md' KEY"} {
		if got := Analyze(source, root, root, check); got != "" {
			t.Errorf("negative-only glob changed default hidden scope: %s: %s", source, got)
		}
	}
}

func TestAudit16WindowsStreams(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows alternate stream policy")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool {
		if _, err := os.Lstat(paths.Resolve(name, cwd, "", root)); os.IsNotExist(err) {
			return false
		}
		return paths.Protected(name, cwd, "", root)
	}
	for _, source := range []string{"cat '.env::$DATA'", "cat .env:missing", "cat .envrc:missing"} {
		if got := Analyze(source, root, root, check); got == "" {
			t.Errorf("protected stream allowed: %s", source)
		}
	}
	if got := Analyze("cat 'public.txt::$DATA'", root, root, check); got != "" {
		t.Errorf("public stream denied: %s", got)
	}
}
