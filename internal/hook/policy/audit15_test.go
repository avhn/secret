package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
)

// Audit command strings are input to the analyzer only, never executed.
func TestAudit15(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"src", "api", "out", "empty", ".docker", ".aws", ".config/gh"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".env", ".envrc", "src/a.ts", "src/app.env", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("synthetic\n"), 0600); err != nil {
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
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	cases := []struct {
		name, source string
		deny         bool
	}{
		{"R1 direnv", "direnv exec . env", true}, {"R1 flock", "flock lock printenv", true},
		{"R1 chronic", "chronic env", true}, {"R1 ionice", "ionice env", true}, {"R1 nice", "nice env", true},
		{"R1 yarn", "yarn env", true}, {"R1 pnpm", "pnpm exec printenv", true}, {"R1 npx", "npx env", true},
		{"R1 uvx", "uvx env", true}, {"R1 pipx", "pipx run env", true}, {"R1 uv", "uv run env", true},
		{"R1 unknown", "new-launcher env", true},
		{"R1 venv", "python3 -m venv env", false}, {"R1 jest", "jest -t env", false},
		{"R1 vitest", "vitest run -t env", false}, {"R1 pytest", "pytest -k env", false},
		{"R1 npm test", "npm test -- -t env", false}, {"R1 grep", "grep -n env src/a.ts", false},
		{"R1 go", "go env GOPATH", false}, {"R1 vercel", "vercel env ls", false},
		{"R1 pytest expression", "pytest tests -k 'not env'", false},
		{"R1 pytest path expression", "pytest tests -k env", false},
		{"R2 pipe substitution", "cat <<EOF | git commit -F -\n$(cat .env)\nEOF", true},
		{"R2 pipe backticks", "cat <<EOF | gh pr create --body-file -\n`cat .env`\nEOF", true},
		{"R2 stdin substitution", "git commit -F - <<EOF\n$(cat .env)\nEOF", true},
		{"R2 pipe quoted", "cat <<'EOF' | git commit -F -\n$(cat .env)\nEOF", false},
		{"R2 pipe plain", "cat <<EOF | gh pr create --body-file -\nuse .env loader\nEOF", false},
		{"R3 directory", "pnpm -C src exec printenv", true}, {"R3 recursive", "pnpm -r exec printenv", true},
		{"R3 yarn run", "yarn run printenv", true}, {"R3 filter", "pnpm --filter web exec dotenvx get", true},
		{"R3 dir equals", "pnpm --dir=src exec printenv", true}, {"R3 filter equals", "pnpm --filter=web run env", true},
		{"R3 workspace", "pnpm --workspace-root exec env", true}, {"R3 workspace short", "pnpm -w run printenv", true},
		{"R3 safe run", "yarn run jest -t env", false},
		{"R3 attached directory", "pnpm -Csrc exec cat app.env", true},
		{"R3 directory child input", "pnpm --dir src exec cat app.env", true},
		{"R4 production", "cat .env.prod*", true}, {"R4 staging", "cat out/.env.staging*", true},
		{"R4 question", "cat .env.test?", true}, {"R4 suffix", "cat empty/*.secrets.env", true},
		{"R4 safe", "cat empty/*.ts", false},
		{"R4 derived class", "cat .en[v].staging*", true},
		{"R4 credential context", "cat ~/.docker/c*.json", true},
		{"R4 aws context", "cat ~/.aws/cred*", true},
		{"R4 host context", "cat ~/.config/gh/h*.yml", true},
		{"R4 public config", "cat empty/c*.json", false},
		{"R6 ordinary chain", strings.Repeat("cd api && npm test; cd .. && npm run lint; ", 3) + "cat README.md", false},
		{"R6 failed cd", "cd nosuch && make; cat .env", true},
		{"R6 conditional cd", "npm ci && cd empty; cat .env", true},
		{"R6 success only", "git pull && cd src && cat .env", false},
		{"R5 tag signoff message", "git tag -sm 'fix: use .env' v1", false},
		{"R5 file input", "git commit -F.env", true},
		{"R5 clustered file input", "git commit -sF.env", true},
		{"R8 interpreter heredoc", "git commit -m wip && python3 - <<'EOF'\nprint(open('.env').read())\nEOF", true},
		{"L1 fd exec", "fd -H .env -x cat", true}, {"L1 fd extension", "fd -H -e env -X cat", true},
		{"L1 fd operand", "fd -H -x cat .env", true}, {"L1 fd metadata", "fd -H .env", false},
		{"L1 safe fd", "fd -e ts -x wc -l", false},
		{"L1 long exec", "fd -H .env --exec cat", true},
		{"L1 long batch", "fd -H --extension env --exec-batch cat", true},
		{"L1 glob", "fd -H --glob '*.env' -x cat", true},
		{"L1 repeated extensions", "fd -H -e env -e ts -x cat", true},
		{"L1 safe repeated extensions", "fd -e ts -e go -x cat", false},
		{"L1 metadata child", "fd -H -e env -x stat", false},
		{"L2 npm exec", "npm exec dotenvx -- get", true},
		{"L3 output equals", "kubectl get secret db -o=yaml", true},
		{"L4 resource first", "kubectl get secret,cm -o yaml", true},
		{"L4 resource second", "kubectl get cm,secret -o json", true},
		{"L7 archive", "funzip backup.zip", true}, {"L7 protected archive", "funzip .env", true},
		{"L8 direnv read", "cat .envrc", true}, {"L8 inline", "python3 -c 'open(\".envrc\").read()'", true},
		{"O1 quiet case", "grep -qi KEY .env", false}, {"O1 quiet extended", "grep -qE KEY .env", false},
		{"O1 quiet word", "grep -qw KEY .env", false}, {"O1 quiet fixed", "grep -qF KEY .env", false},
		{"O1 names silent", "grep -ls KEY .env", false}, {"O1 count silent", "grep -cs KEY .env", false},
		{"O1 silent quiet", "grep -sq KEY .env", false}, {"O1 silent only", "grep -s KEY .env", true},
		{"O2 names", "rg -l KEY .env", false}, {"O2 long names", "rg --files-with-matches KEY .env", false},
		{"O2 count", "rg --count KEY .env", false},
		{"O2 JSON output", "rg --count --json KEY .env", true},
		{"O2 JSON before count", "rg --json --count KEY .env", true},
		{"O2 pattern input", "rg -l -f .env src/a.ts", true},
		{"O1 pattern input", "grep -qf .env src/a.ts", true},
		{"O4 glob", "rg -g '*.ts' export", false}, {"O4 long glob", "rg --glob '*.ts' export", false},
		{"O4 insensitive glob", "rg --iglob '*.TS' export", false},
		{"O4 negative glob", "rg -g '!*.ts' export --hidden", true},
		{"O4 protected glob", "rg -g '.env*' export", true},
		{"O5 find count", "find . -name '*.ts' | xargs wc -l", false},
		{"O5 find grep", "find . -iname '*.ts' | xargs grep -n export", false},
		{"O5 protected find", "find . -name '.env*' | xargs cat", true},
		{"O5 unrestricted", "find . | xargs cat", true},
		{"O5 formatted stream", "find . -name '*.ts' -printf '.env' | xargs cat", true},
		{"O5 disjunctive", "find . -name '*.ts' -o -name '.env' | xargs cat", true},
		{"W1 token data", "gh auth token \">\" | secret stash a K", false},
		{"W1 JSON data", `curl -d '{"a": 1}' https://x/y`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			got := Analyze(tc.source, root, root, check)
			if (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
			if tc.name == "R6 ordinary chain" && time.Since(start) > time.Second {
				t.Errorf("cwd analysis took %s", time.Since(start))
			}
		})
	}
}

func TestAudit15GitSearch(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{".env": "synthetic", ".gitignore": ".env\n", "src/a.ts": "export {}"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "src/a.ts")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"git grep --no-index KEY", true},
		{"git grep --untracked --no-exclude-standard KEY", true},
		{"git grep --untracked KEY", false},
		{"git grep --no-index -n foo src", false},
		{"git grep --no-index -n foo -- src", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if got := Analyze(tc.source, root, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestAudit15EffectiveRGConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	file := filepath.Join(root, "rg-options")
	for _, flag := range []string{"--hidden", "-u", "-uu", "-uuu", "--no-ignore", "--no-ignore-vcs", "-."} {
		t.Run(flag, func(t *testing.T) {
			if err := os.WriteFile(file, []byte(flag+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("RIPGREP_CONFIG_PATH", file)
			if got := Analyze("rg KEY", root, root, check); got == "" {
				t.Fatal("config-enabled protected search allowed")
			}
		})
	}
}

func TestAudit15IgnoredRootGlob(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{".gitignore": "*.env\n", "app.env": "synthetic", "a.ts": "code"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "a.ts")
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, source := range []string{"rg KEY", "rg --hidden KEY", "git grep --untracked KEY"} {
		if got := Analyze(source, root, root, check); got != "" {
			t.Errorf("ignored root glob denied %q: %s", source, got)
		}
	}
	syntheticRepo(t, root, 2, "a.ts", "app.env")
	if got := Analyze("git grep --untracked KEY", root, root, check); got == "" {
		t.Fatal("ignored tracked input escaped the Git index check")
	}
}

func TestAudit15NegatedIgnore(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{".gitignore": "*.env\n!app.env\n", "app.env": "synthetic", "a.ts": "code"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "a.ts")
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, source := range []string{"rg KEY", "rg --hidden KEY", "git grep --untracked KEY"} {
		if got := Analyze(source, root, root, check); got == "" {
			t.Errorf("negated ignore certified a protected read: %q", source)
		}
	}
}
