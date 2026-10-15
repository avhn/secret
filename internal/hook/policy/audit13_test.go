package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
)

// Commands are parsed only; fixture files never contain real credentials.
func TestAudit13(t *testing.T) {
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	root := t.TempDir()
	for _, dir := range []string{"src", "packages/api", "build"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", "src/util.ts", "packages/api/package.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "src/util.ts", "packages/api/package.json")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	cases := []struct {
		cmd  string
		deny bool
	}{
		{`docker-compose config`, true}, {`docker-compose convert`, true}, {`docker compose convert`, true},
		{`dotenvx get`, true}, {`dotenvx get API_KEY`, true}, {`dotenvx decrypt --stdout`, true}, {`dotenv get API_KEY`, true}, {`python3 -m dotenv get API_KEY`, true},
		{`npx dotenv -p K`, true}, {`npx dotenv-cli -p K`, true}, {`pnpm dlx dotenv-cli -p K`, true}, {`bunx dotenv -p K`, true}, {`npx dotenvx get`, true}, {`uv run dotenv list`, true}, {`poetry run dotenv list`, true}, {`yarn dlx dotenv get K`, true}, {`pnpm exec dotenv get K`, true}, {`pipx run dotenv get K`, true},
		{`gh config get oauth_token -h github.com`, true},
		{`php -i`, true}, {`php --info`, true}, {`php -r 'phpinfo();'`, true}, {`php -r 'print_r($_SERVER);'`, true}, {`php -r 'var_dump($_ENV);'`, true},
		{`pnpm config get //registry.npmjs.org/:_authToken`, true}, {`pnpm config list`, true}, {`yarn config list`, true},
		{`docker inspect app`, true}, {`docker inspect --format '{{.Config.Env}}' app`, true}, {`docker inspect -f '{{json .Config.Env}}' app`, true}, {`docker container inspect --format '{{.Config.Env}}' app`, true}, {`docker image inspect app`, false}, {`docker inspect --format '{{.Id}}' app`, false},
		{`kubectl get secret app -o yaml`, true}, {`kubectl get secret app -o json`, true}, {`kubectl get secret app -o jsonpath='{.data}'`, true}, {`kubectl get secret app -o go-template='{{.data}}'`, true}, {`kubectl get secrets`, false}, {`kubectl describe secret app`, false},
		{`python -c 'from dotenv import dotenv_values; print(dotenv_values())'`, true}, {`curl file://$PWD/.env`, true}, {`zip - .env`, true},
		{`git grep -n process.env`, false}, {`git grep -e process.env`, false}, {`git log -S process.env`, false},
		{`sed -n '/process.env/p' src/util.ts`, false}, {`sed -n '/import.meta.env/p' src/util.ts`, false},
		{`cat src/*`, false}, {`grep foo src/*`, false}, {`wc -l src/*`, false}, {`cp src/* build/`, false}, {`cp -r packages/* build/`, false}, {`cat build/*`, true},
		{`grep -rl foo src`, false}, {`grep -ri foo src`, false}, {`grep -rn --include='*.ts' foo .`, false}, {`grep -r foo src`, false}, {`grep -R foo src`, false},
		{`rg API_KEY`, false}, {`rg --type ts useEffect`, false},
		{`docker run --rm -v $PWD:/src img`, false}, {`docker run --rm -v ${PWD}:/src img`, false}, {`docker run --rm -v $(pwd):/src img`, false},
		{`psql "$DATABASE_URL" -c 'select 1'`, false}, {`curl -sS "$API_URL/health"`, false}, {`curl -H "Authorization: Bearer $GITHUB_TOKEN" u`, false},
		{`npm test -- "$TEST_FILE"`, false}, {`kill $(cat build/app.pid)`, false}, {`git tag v$(node -p "require('./package.json').version")`, false},
		{`for f in src/*.ts; do wc -l "$f"; done`, false}, {`npm version patch`, false}, {`unzip -o build/assets.zip`, false},
		{`sed -i '' 's/foo/bar/' src/util.ts`, false}, {`touch ''`, false},
		{`set -e && cd packages/api && npm ci`, false}, {`true && cd src && npm test`, false},
		{`docker ps -q | xargs docker stop`, false}, {"echo ok\r\n", false},
		{`cat .env`, true}, {`grep -r foo .`, true}, {`rg --hidden API_KEY`, true}, {`cat *`, true},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			if got := Analyze(tc.cmd, root, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestAudit13ParityReproducers(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"home", "src", "sub"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"src/a.ts", "sub/.env", "sub/app.env"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		deny          bool
	}{
		{"final CR", "true\r", false},
		{"CRLF", "cat src/a.ts\r\n", false},
		{"embedded CR", "true\rtrue", true},
		{"write after heredoc", "cat <<'EOF' > src/env.ts\nprocess.env.PORT\nEOF", false},
		{"append before heredoc", "cat >> .gitignore <<'EOF'\n.env.local\nEOF", false},
		{"unmatched private glob", "cat ~/.ssh/id_*", true},
		{"unmatched glob with literal store", "cat ~/.ssh/id_* .env", true},
		{"multiple roots with protected visible file", "rg TOKEN src sub", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze(tc.command, root, home, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Analyze("cat ~/.ssh/id_*", root, home, check); got == "" {
		t.Fatal("matched private glob allowed")
	}
}

func TestAudit13RecursiveInclude(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env.ts"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	if got := Analyze("grep -rn --include='*.ts' x .", root, root, check); got == "" {
		t.Fatal("included protected dotfile allowed")
	}
	if err := os.Remove(filepath.Join(root, ".env.ts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, ".secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".secrets", "nested.ts"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Analyze("grep -rn --include='*.ts' x .", root, root, check); got == "" {
		t.Fatal("included protected nested file allowed")
	}

	if got := Analyze("kubectl get secret app -o yaml", root, root, check); got != "credential printer requires a direct pipe to secret stash FILE KEY" {
		t.Fatalf("wrong Kubernetes printer role: %q", got)
	}
}

func TestAudit13IgnoredSearch(t *testing.T) {
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	root := t.TempDir()
	for name, value := range map[string]string{"app.secret": "synthetic", ".gitignore": "app.secret\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	if err := os.Mkdir(filepath.Join(root, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := Analyze("rg TOKEN", root, root, check); got != "" {
		t.Logf("rg scope roots=%q fallback=%v protected=%v", rgRoots([]string{"TOKEN"}), (&analyzer{protected: check, home: root, deadline: time.Now().Add(time.Second)}).rgVisibleSafe([]string{"TOKEN"}, root), check(".", root))
		t.Fatalf("ignored search denied: %q", got)
	}
	if got := Analyze("rg --no-ignore TOKEN", root, root, check); got == "" {
		t.Fatal("unignored protected file allowed")
	}
}
