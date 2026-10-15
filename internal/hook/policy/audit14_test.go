package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestAudit14BudgetReason(t *testing.T) {
	root := t.TempDir()
	got := Analyze("true "+strings.Repeat("x", 8200), root, root, func(string, string) bool { return false })
	if !strings.Contains(got, "split the command") {
		t.Fatalf("budget denial did not explain how to split: %q", got)
	}
}

// Commands are parsed as text only. All paths and contents are synthetic.
func TestAudit14(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"sub", "src", "conf", "home/.aws", "out", "build"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".env", "sub/app.env", "conf/app.env", "home/.aws/credentials", "src/a.ts"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	cases := []struct {
		command string
		deny    bool
	}{
		{"git commit -F - <<'EOF'\nuse .env loader\nEOF", false},
		{"git commit --file=- <<'EOF'\nread process.env\nEOF", false},
		{"cat <<'EOF' | git commit -F -\nuse .env loader\nEOF", false},
		{"git tag -a v1 -F - <<'EOF'\nuse .env loader\nEOF", false},
		{"gh pr create --body-file - <<'EOF'\nread .env\nEOF", false},
		{"git commit -am 'fix: read PORT from process.env'", false},
		{"git commit -am 'fix: use .env loader'", false},
		{"env", true}, {"printenv", true}, {"docker exec c env", true}, {"kubectl exec p -- env", true},
		{"python3 -m venv env", false}, {"jest -t env", false}, {"vitest run -t env", false},
		{"pytest -k env", false}, {"pytest tests -k 'not env'", false}, {"npm test -- -t env", false},
		{"grep -rn env src", false}, {"grep -n env .gitignore", false}, {"go env GOPATH", false}, {"vercel env ls", false},
		{"pnpm config get registry", false}, {"yarn config get npmRegistryServer", false},
		{"pnpm config get //registry/:_authToken", true}, {"yarn config get password", true},
		{"pnpm -C src config ls", true}, {"yarn --dir src config list", true}, {"pnpm --filter app config get credential", true},
		{"kubectl get secret/db -o yaml", true}, {"kubectl get secrets/db -ojson", true},
		{"kubectl -n prod get secret db -oyaml", true}, {"kubectl get secret db --namespace prod -ojsonpath='{.data}'", true},
		{"gh config get -h github.com oauth_token", true}, {"gh config get --host github.com oauth_token", true},
		{"pipx run --spec python-dotenv dotenv list", true}, {"npx dotenvx@latest get", true},
		{"npx @dotenvx/dotenvx get", true}, {"npm exec -- dotenvx get", true},
		{"yarn dotenvx get", true}, {"pnpm dotenvx get", true}, {"uvx --from python-dotenv dotenv list", true},
		{"docker inspect --format json web", true}, {"docker container inspect web --format=json", true},
		{"rg KEY ~/.aws", true}, {"rg -n DATABASE_URL ../sub", true},
		{"tar xzf backup.tgz && cat restored/.env*", true},
		{"unzip -o creds.zip -d out && cat out/*.env", true},
		{"git stash pop && cat .env.*", true},
		{"cp -r ../shared/config . && cat config/*.env", true},
		{"cat src/*.ts", false}, {"npm ci && cd /tmp/empty; cat conf/*", true},
		{"docker cp $C:/app/.env ./out.env", true},
		{"grep -rn --include=*.ts KEY src", false},
		{"npx dotenv -e .env.test -- jest", false},
		{"rg -l API_KEY --hidden", false},
		{"gh secret set API_KEY < /dev/null", false},
		{"python3 -c \"from dotenv import load_dotenv; load_dotenv(); import app\"", false},
		{"git rm --cached .env", false}, {"fd -H .env", false},
		{"grep -q API_KEY .env", false}, {"grep -c API_KEY .env", false},
		{"grep -q -f .env src/a.ts", true},
		{"python3 -c \"from dotenv import load_dotenv; load_dotenv(); print(open('.env').read())\"", true},
		{"dotenvx run -f .env.production -- node app.js", false},
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("sub/app.env\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Analyze("rg KEY sub", root, home, check); got == "" {
		t.Error("non-repository .gitignore exempted visible protected input")
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			if got := Analyze(tc.command, root, home, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}
