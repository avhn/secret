package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// Commands are policy input only, never executed. HOME and every file are synthetic.
func TestAudit17(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"home/.aws", "home/.ssh", "clean/src", "proj/src", "ext"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"home/.aws/credentials", "home/.aws/config.json", "home/.ssh/id_ed25519", "clean/src/a.ts", "proj/README.md", "proj/.env", "proj/app.secret", "ext/.env.ts"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, filepath.Join(root, "proj"), 2)
	t.Setenv("HOME", home)
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, tc := range []struct {
		name, source, dir string
		deny              bool
	}{
		{"D1 find home store", "find ~/.aws | xargs cat", "clean", true},
		{"D1 find type", "find ~/.aws -type f | xargs cat", "clean", true},
		{"D1 find home filter", "find ~ -name '*.json' | xargs cat", "clean", true},
		{"D1 find external", "find ../proj -type f | xargs grep -n T", "clean", true},
		{"D1 find null", "find ../proj -type f -print0 | xargs -0 head", "clean", true},
		{"D1 find multiple roots", "find src ../proj -type f | xargs cat", "clean", true},
		{"D1 find selected credential", "find ../ext -name '*.ts' | xargs cat", "clean", true},
		{"D1 find clean filter", "find src -name '*.ts' | xargs wc -l", "clean", false},
		{"D1 find clean root", "find src -type f | xargs cat", "clean", false},
		{"D1 find dynamic root", "find \"$UNKNOWN\" -type f | xargs cat", "clean", true},
		{"D1 transformed listing", "find ../proj | sort | xargs cat", "clean", true},
		{"D1 subshell listing", "(find ../proj) | xargs cat", "clean", true},
		{"D1 wrapped producer", "timeout 5 find ../proj | xargs cat", "clean", true},
		{"D1 wrapped consumer", "find ../proj | env xargs cat", "clean", true},
		{"D1 assigned consumer", "find ../proj | LANG=C xargs cat", "clean", true},
		{"D1 env producer cwd", "env -C ../proj find . | xargs cat", "clean", true},
		{"D1 clean wrapped producer", "timeout 5 find src -name '*.ts' | xargs wc -l", "clean", false},
		{"D1 clean wrapped consumer", "find src -name '*.ts' | env xargs wc -l", "clean", false},
		{"D1 ls external", "ls -A ../proj | xargs -I{} cat ../proj/{}", "clean", true},
		{"D1 ls multiple roots", "ls src ../proj | xargs cat", "clean", true},
		{"D1 ls clean", "ls src | xargs cat", "clean", false},
		{"D1 public file from dirty cwd", "ls ../clean/src/a.ts | xargs cat", "proj", false},
		{"D1 filtered root from dirty cwd", "find ../clean/src -name '*.ts' | xargs cat", "proj", false},
		{"D1 command prefix from dirty cwd", "command find ../clean/src -name '*.ts' | xargs wc -l", "proj", false},
		{"D1 fd root from dirty cwd", "fd -e ts . ../clean/src | xargs cat", "proj", false},
		{"D1 git external", "git -C ../proj ls-files -o | xargs cat", "clean", true},
		{"D1 git attached root", "git -C../proj ls-files -o | xargs cat", "clean", true},
		{"D1 git inline worktree", "GIT_WORK_TREE=../proj git ls-files -o | xargs cat", "clean", true},
		{"D1 git prior worktree", "export GIT_WORK_TREE=../proj; git ls-files -o | xargs cat", "clean", true},
		{"D1 git explicit worktree", "git --work-tree=../proj ls-files -o | xargs cat", "clean", true},
		{"D1 git parent pathspec", "git -C ../proj/src ls-files -o -- .. | xargs cat", "clean", true},
		{"D1 git top pathspec", "git -C ../proj/src ls-files -o -- ':(top)*' | xargs cat", "clean", true},
		{"D1 git absolute pathspec", "git -C ../proj/src ls-files -o -- '" + filepath.ToSlash(filepath.Join(root, "proj", ".env")) + "' | xargs cat", "clean", true},
		{"D1 rg external", "rg --files ../proj | xargs cat", "clean", true},
		{"D1 rg multiple roots", "rg --files src ../proj | xargs cat", "clean", true},
		{"D1 rg clean", "rg --files src | xargs cat", "clean", false},
		{"D2 npx call", "npx -c 'cat .env'", "proj", true},
		{"D2 npx long call", "npx --call 'printenv TOKEN'", "clean", true},
		{"D2 npx attached short", "npx -c'cat .env'", "proj", true},
		{"D2 npx attached long", "npx --call='cat .env'", "proj", true},
		{"D2 npm call", "npm exec -c 'cat .env'", "proj", true},
		{"D2 npm attached call", "npm exec --call='printenv TOKEN'", "clean", true},
		{"D2 yarn exec", "yarn exec 'cat .env'", "proj", true},
		{"D2 yarn separator", "yarn exec -- 'printenv TOKEN'", "clean", true},
		{"D2 yarn silent", "yarn exec --silent 'printenv TOKEN'", "clean", true},
		{"D2 pnpm call", "pnpm exec -c 'cat .env'", "proj", true},
		{"D2 safe npx call", "npx -c 'echo ok'", "clean", false},
		{"D2 safe npm call", "npm exec --call='echo ok'", "clean", false},
		{"D2 safe yarn call", "yarn exec 'echo ok'", "clean", false},
		{"D2 safe pnpm call", "pnpm exec -c 'echo ok'", "clean", false},
		{"D3 dotted aws", "cat ~/.aws/./credentials", "clean", true},
		{"D3 cwd aws", "cd ~/.aws && cat ./credentials", "clean", true},
		{"D3 cwd ssh", "cd ~/.ssh; cat ./id_ed25519", "clean", true},
		{"D4 background", "cd src & cat .env", "proj", true},
		{"D4 background block", "{ cd src; } & cat .env", "proj", true},
		{"D4 background chain", "true && cd src & cat .env", "proj", true},
		{"D4 subshell", "( cd src ); cat .env", "proj", true},
		{"D4 while", "while false; do cd src; done; cat .env", "proj", true},
		{"D4 for", "for x in a; do cd src; done; cat .env", "proj", true},
		{"D4 if", "if true; then cd src; fi; cat .env", "proj", true},
		{"D4 safe background", "cd src & cat src/a.ts", "clean", false},
		{"D4 safe zero iteration", "while false; do cd src; done; cat README.md", "proj", false},
		{"D5 mixed braces", "rg --iglob '{*.secret,!*.md}' K", "proj", true},
		{"D6 npm alias", "npm run-script env", "clean", true},
		{"D6 npm silent", "npm -s run env", "clean", true},
		{"D6 npm prefix", "npm --prefix src rum env", "clean", true},
		{"D6 npm workspace", "npm --workspace web urn env", "clean", true},
		{"D6 python dotenv", "python3 -m dotenv run -- env", "clean", true},
		{"D6 dotenv", "dotenv run -- env", "clean", true},
		{"D7 fdfind exec", "fdfind -H .env -x cat", "proj", true},
		{"D7 fdfind pipe", "fdfind -H . ../proj | xargs cat", "clean", true},
		{"D7 fd safe exec", "fd -e ts -x gofmt -l", "clean", false},
		{"D7 fdfind safe exec", "fdfind -e ts -x gofmt -l", "clean", false},
		{"D7 fdfind names", "fdfind -H .env", "proj", false},
		{"D8 keyring", "keyring get SVC USER", "clean", true},
		{"D8 module keyring", "python3 -m keyring get SVC USER", "clean", true},
		{"D8 keyring help", "keyring --help", "clean", false},
		{"D10 pnpm dlx", "pnpm dlx --silent dotenvx get K", "clean", true},
		{"D10 yarn dlx", "yarn dlx -s dotenvx get K", "clean", true},
		{"D10 pnpm package", "pnpm dlx --package dotenvx dotenvx get K", "clean", true},
		{"D10 yarn package", "yarn dlx --package=dotenvx dotenvx get K", "clean", true},
		{"D10 npx package", "npx -p dotenvx printenv", "clean", true},
		{"D10 bunx package", "bunx -p dotenvx printenv", "clean", true},
		{"D10 safe pnpm", "pnpm dlx --silent jest -t env", "clean", false},
		{"D10 safe yarn", "yarn dlx --package=jest jest -t env", "clean", false},
		{"D10 safe npx", "npx -p jest jest -t env", "clean", false},
		{"D10 safe bunx", "bunx --package jest jest -t env", "clean", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cwd := filepath.Join(root, tc.dir)
			if got := Analyze(tc.source, cwd, home, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
			if got := AnalyzeArgv([]string{"bash", "-c", tc.source}, cwd, home, check); (got != "") != tc.deny {
				t.Errorf("argv denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestAudit17ProducerSymlinkRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	root := t.TempDir()
	for _, dir := range []string{"home", "clean", "ext"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "ext", ".env.ts"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../ext", filepath.Join(root, "clean", "shared")); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, source := range []string{"find -L . -name '*.ts' | xargs cat", "find shared -name '*.ts' | xargs cat", "fd -e ts . shared | xargs cat", "fdfind -e ts . shared | xargs cat", "ls shared | xargs cat", "rg --files shared | xargs cat"} {
		if got := Analyze(source, filepath.Join(root, "clean"), home, check); got == "" {
			t.Errorf("symlink producer allowed: %s", source)
		}
	}
}

func TestAudit17AncestorIgnoreOverrides(t *testing.T) {
	for _, ignore := range []string{".ignore", ".rgignore"} {
		t.Run(ignore, func(t *testing.T) {
			root := t.TempDir()
			project := filepath.Join(root, "project")
			if err := os.MkdirAll(project, 0700); err != nil {
				t.Fatal(err)
			}
			for name, data := range map[string]string{".gitignore": "prod.env\n", "prod.env": "synthetic\n"} {
				if err := os.WriteFile(filepath.Join(project, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			syntheticRepo(t, project, 2)
			t.Setenv("HOME", filepath.Join(root, "home"))
			t.Setenv("RIPGREP_CONFIG_PATH", "")
			check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
			if got := Analyze("rg K", project, root, check); got != "" {
				t.Fatalf("plain ignored file denied: %s", got)
			}
			if err := os.WriteFile(filepath.Join(root, ignore), []byte("!prod.env\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if got := Analyze("rg K", project, root, check); got == "" {
				t.Fatal("ancestor ignore above work tree certified a credential search")
			}
		})
	}
}

func TestAudit17MixedIgnoredGlobs(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2)
	for name, data := range map[string]string{".gitignore": "*.secret\n", "prod.secret": "synthetic\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := filepath.Abs("../../../examples/ripgreprc")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("RIPGREP_CONFIG_PATH", config)
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, source := range []string{"rg --iglob '{*.secret,!*.md}' K", "rg --iglob '{!*.md,*.secret}' K"} {
		if got := Analyze(source, root, root, check); got == "" {
			t.Errorf("mixed brace glob certified an ignored credential: %s", source)
		}
	}
	if got := Analyze("rg --iglob '{!*.md,!*.txt}' K", root, root, check); got != "" {
		t.Errorf("pure exclusions lost the protective config proof: %s", got)
	}
}

func TestAudit17AncestorIgnoreBudget(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for i := 0; i < 129; i++ {
		root = filepath.Join(root, "d")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	a := &analyzer{home: home}
	if a.visibleRootSafe(root, root, true, false) {
		t.Fatal("exhausted ancestor walk certified without reaching the filesystem root")
	}
}

func TestAudit17PackageCallsAreNotChildren(t *testing.T) {
	for _, name := range []string{"npx", "npm", "pnpm", "yarn"} {
		for _, call := range [][]string{{"-c", "cat .env"}, {"--call", "printenv TOKEN"}, {"-ccat .env"}, {"--call=cat .env"}} {
			args := call
			if name != "npx" {
				args = append([]string{"exec"}, call...)
			}
			if child, peeled := safePackageChild(name, args); peeled {
				t.Errorf("%s shell call peeled into child %q", name, child)
			}
		}
	}
	if child, peeled := safePackageChild("yarn", []string{"exec", "cat .env"}); peeled {
		t.Errorf("yarn exec shell string peeled into child %q", child)
	}
}
