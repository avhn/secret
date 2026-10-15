package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
)

// Analyze source strings only: never execute these commands.
func TestP19Fixes(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"sub", "sepgd/objects", "sepgd/refs", "bare/objects", "bare/refs", ".git/objects", ".git/refs", "packages/pkg", "src"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, value := range map[string]string{"sepgd/HEAD": "ref: refs/heads/main\n", "bare/HEAD": "ref: refs/heads/main\n", ".git/HEAD": "ref: refs/heads/main\n", "src/a.ts": "safe", "packages/pkg/package.json": "{}", ".env": "fixture"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(root, "bare"), filepath.Join(root, "sub", "alias")); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	cases := []struct {
		source string
		deny   bool
	}{
		{`cat packages/*/package.json`, false}, {`eslint src/**/*.ts`, false},
		{`f='.[e]nv'; cat $f`, true}, {`f='src/*.ts'; cat $f`, false},
		{"git commit -m \"$(cat <<'EOF'\n.env loader\nEOF\n)\"", false},
		{"git commit -F \"$(cat <<'EOF'\n.env loader\nEOF\n)\"", true},
		{"gh pr create --body-file \"$(cat <<'EOF'\n.env loader\nEOF\n)\"", true},
		{"gh pr create --body \"$(cat <<'EOF'\n.env loader\nEOF\n)\"", false},
		{`python3 <<<'open("../sepgd/config","w")'`, true},
		{"python3 <<'EOF'\nopen(\"bare/config\",\"w\")\nEOF", true},
		{`node <<<'fs.writeFileSync("bare/config","x")'`, true},
		{`perl <<<'open F,">bare/config"'`, true},
		{`python3 -c 'open("bare/config","w")'`, true},
		{`python3 -c 'open("sub/alias/config","w")'`, true},
		{`docker run -v .env:/src image`, true}, {`docker create --volume=.env:/src image`, true},
		{`docker run --mount type=bind,src=.env,dst=/src image`, true},
		{`docker run -v "$PWD":/src node:20 npm test`, false},
		{`GIT_CONFIG_GLOBAL=x git status`, true}, {`GIT_CONFIG_SYSTEM=x git status`, true}, {`GIT_CONFIG_PARAMETERS=x git status`, true},
		{`make --e='x:;printenv'`, true}, {`make --ev='x:;printenv'`, true}, {`make --eva='x:;printenv'`, true},
		{`make -sf -`, true}, {`make -nf -`, true}, {`make -sf/dev/stdin`, true},
		{"make --eval='x:\n\t+printenv'", true}, {"make --eval='x:\n\t@env'", true},
		{`gmake --eval='x:;printenv'`, true}, {`gmake --eval=x`, true}, {`make -p`, true}, {`gmake -p`, true},
		{`dotenv list`, true}, {`python3 -m dotenv list`, true}, {`docker compose config`, true},
		{`gh api r -F input=@.env`, true}, {`gh api r -f input=@.env`, true},
		{`gh api r --field input=@.env`, true}, {`gh api r --raw-field=input=@.env`, true},
		{`machinectl shell root@.host`, true}, {`systemd-run -S true`, true},
		{`sed -i 's/a/b/' src/*.ts`, false}, {`grep -rn foo src`, false},
		{`git config user.name`, false}, {`git config --get x`, false}, {`git clean -n`, false},
		{`git clone --recurse-submodules u x`, false}, {`git clone -c init.defaultBranch=main u x`, false},
		{`git apply --check -C3 p.diff`, false}, {`cd bare && git log`, false},
		{`git stash`, false}, {`kubectl create secret generic s --from-env-file=.env`, false},
		{`git ls-files -o -X .env`, false}, {`pm2 env 0`, true},
		{`curl -d '{"a": 1}' https://x/y`, false}, {`gh api r --jq '.[] | .title'`, false},
		{`sqlite3 db 'select * from t'`, false}, {`gh auth token ">" | secret stash a K`, false},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			cwd := root
			if runtime.GOOS == "windows" && tc.source == `python3 -c 'open("sub/alias/config","w")'` {
				t.Skip("symlink creation needs Windows developer mode")
			}
			if tc.source == `python3 <<<'open("../sepgd/config","w")'` {
				cwd = filepath.Join(root, "sub")
			}
			if got := Analyze(tc.source, cwd, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q, want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestP19GlobClasses(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a1", "ab", "a!", "plain"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for pattern, want := range map[string]int{"a[!b]": 2, "a[^b]": 2, "a[[:digit:]]": 1, "a[[:alpha:]]": 1, "p*": 1} {
		got, ok := shellGlobMatches(pattern, root, time.Now().Add(time.Second))
		if !ok || len(got) != want {
			t.Errorf("%s: paths=%v ok=%v, want %d", pattern, got, ok, want)
		}
	}
	if runtime.GOOS == "windows" {
		t.Log("Windows fixture names avoid invalid wildcard characters")
	}
}
