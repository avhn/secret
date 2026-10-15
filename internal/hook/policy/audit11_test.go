package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestAuditEleven treats all strings as hook input, never as commands to execute.
func TestAuditEleven(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"home", "src", "build", "dist", "bare", "sepgd", "tmpl/hooks", "sub"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"bare", "sepgd"} {
		for _, d := range []string{"objects", "refs"} {
			if err := os.MkdirAll(filepath.Join(root, dir, d), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, dir, "HEAD"), []byte("ref: refs/heads/main\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"f", "x", "p.patch", "list", "z.zip", "t.tar", "a.tar", "a.zip", "a.7z", "in", "sub/Makefile"} {
		if err := os.WriteFile(filepath.Join(root, p), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(root, "home")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	tests := []struct {
		command, cwd string
		deny         bool
	}{
		{"tar -xf t.tar -C bare", root, true}, {"tar --directory bare -xf t.tar", root, true}, {"tar -xf t.tar -Cbare", root, true},
		{"tar -xvCbare -f a.tar", root, true}, {"gtar -xf t.tar -C bare", root, true},
		{"tar -xf ../t.tar", filepath.Join(root, "bare"), true}, {"cp x config", filepath.Join(root, "bare"), true},
		{"cp -r tmpl/hooks bare", root, true}, {"rsync -a tmpl/ bare", root, true}, {"cp x bare", root, true}, {"mv x bare", root, true},
		{"cp x sepgd", root, true}, {"cp -t sepgd x", root, true}, {"install x sepgd", root, true}, {"cp --targ=sepgd x", root, true},
		{"tar -xf t.tar -C sepgd", root, true}, {"unzip -o z.zip -d bare", root, true},
		{"git apply --stat --apply p.patch", root, true}, {"git apply --check --apply p.patch", root, true}, {"git apply --stat --unsafe-paths p.patch", root, true},
		{"git init --template=../tmpl", root, true}, {"git init --templ=../tmpl", root, true}, {"git init --template ../tmpl", root, true}, {"GIT_TEMPLATE_DIR=../tmpl git init", root, true},
		{"git --git-dir=bare init --template=../tmpl", root, true}, {"git clone --template=../tmpl https://example.invalid/project", root, true},
		{"git init -c core.hooksPath=x", root, true}, {"git clone -c core.hooksPath=x https://example.invalid/project", root, true},
		{"git init --bare gd && echo y >> gd/config", root, true}, {"git clone --bare https://example.invalid/project gd && echo y >> gd/config", root, true},
		{"git clone --mirror https://example.invalid/project gd && echo y >> gd/config", root, true},
		{"d=build;read d<f;echo x > $d/pre-commit", root, true}, {"d=build&&read d<f&&echo x > $d/pre-commit", root, true},
		{"d=build; printf -vd x; echo x > $d/pre-commit", root, true}, {"d=build; printf -v d[0] x; echo x > $d/pre-commit", root, true},
		{"d=build; d[0]=bare; echo x > $d/hooks/pre-commit", root, true}, {"d=build; declare -n link=other; echo x > $d/pre-commit", root, true},
		{"make -f - <<<'all: ; @cat .netrc'", root, true}, {"make --makefile=/dev/stdin <<<'all: ; @cat .netrc'", root, true},
		{"echo 'x:;cat .env' | make -f -", root, true}, {"make --eval 'all: ; @printenv'", root, true},
		{"make -E 'all: ; @printenv'", root, true}, {"make --eval='x:;@printenv'", root, true},
		{"make -E 'x: ; +env'", root, true}, {"make 'X=$(shell cat .netrc)'", root, true}, {"make -f<(echo x)", root, true},
		{"echo printenv | doas -u root -s", root, true}, {"echo printenv | expect -i", root, true}, {"echo printenv | run0 -u root", root, true},
		{"echo printenv | runuser -u root", root, true}, {"echo printenv | runuser -l root", root, true},
		{"echo printenv | machinectl shell root@", root, true}, {"echo printenv | pkexec --user root", root, true},
		{"echo printenv | systemd-run -S", root, true}, {"echo printenv | doas -n -s", root, true},
		{"echo printenv | expect -df -", root, true}, {"echo printenv | expect -nf -", root, true}, {"echo printenv | expect -f/dev/stdin", root, true},
		{"npm exec --call printenv", root, true}, {"npx --call=env", root, true}, {"npm x -c printenv", root, true},
		{"npm --yes exec -c printenv", root, true}, {"npx -cprintenv", root, true}, {"gh alias set --shell x printenv", root, true},
		{"flock --co=printenv", root, true}, {"flock --comm=env", root, true}, {"runuser --comm=printenv", root, true},
		{"rsync -azeprintenv a b", root, true}, {"compgen -e", root, true}, {"compgen -v", root, true},
		{"python3 -c 'open(\"sepgd/config\",\"w\")'", root, true},
		{"python3 <<'EOF'\nprint(open('.env').read())\nEOF", root, true},
		{"node <<<'require(\"fs\").writeFileSync(\".git/config\",\"x\")'", root, true},
		{"perl <<'EOF'\nopen F, '.env';\nEOF", root, true},
		{"ruby <<'EOF'\nFile.write('.git/config','x')\nEOF", root, true},
		{"foo --cmd 'source .netrc'", root, true},
		{"foo --cmd '<.netrc'", root, true},
		{"git init --separate-git-dir=newgd", root, true},
		{"xargs -a list cat", root, true},
		{"git commit -F - <<'EOF'\nfeat: secret exec and cat .env are prose\nEOF", root, true},
		{"git commit -m \"$(cat <<'EOF'\nmsg line\n\nbody\nEOF\n)\"", root, false},
		{`eval "$(cat <<'EOF'
printenv
EOF
)"`, root, true},
		{`git commit -m "$(cat <<'EOF'
see .env docs
EOF
)"`, root, false},
		{"gh pr create --title t --body \"$(cat <<'EOF'\n## Summary\n- x\nEOF\n)\"", root, false},
		{"docker run -v \"$PWD\":/src node:20 npm test", root, false},
		{"find -L . -fprint0 output", root, false},
		{"find -L . -fprint0 bare/config", root, true},
		{"make", root, false}, {"make test", root, false}, {"make -C sub -j 4", root, false}, {"make VAR=1", root, false},
		{"npm exec eslint .", root, false}, {"npx prettier --check .", root, false},
		{"tar -xf a.tar -C build", root, false}, {"cp -r a dist", root, false},
		{"unzip a.zip", root, false}, {"unzip a.zip -d out", root, false}, {"7z x a.7z", root, false}, {"7z x a.7z -oout", root, false},
		{"for f in a b; do cp $f dist/; done", root, false},
		{"unknown --title '.env'", root, true},
		{"gh pr create --body 'see .env docs'", root, false},
		{"echo 'see .git/config docs' > notes.md", root, false},
		{"cat > src/big.ts <<'X'\n" + strings.Repeat("a", 400<<10) + "\nX", root, false},
		{"cat > src/big.ts <<'X'\n" + strings.Repeat("a", 400<<10) + "\nsee .env in docs\nX", root, false},
		{strings.Repeat("true\n", 9000) + "x; echo y > .git/config", root, true},
	}
	for _, tc := range tests {
		t.Run(tc.command[:min(len(tc.command), 90)], func(t *testing.T) {
			got := Analyze(tc.command, tc.cwd, home, check)

			if (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
	for _, cmd := range []string{"foo --cmd 'source .netrc'", "foo --cmd '<.netrc'"} {
		if got := Analyze(cmd, root, home, func(string, string) bool { return false }); got == "" {
			t.Errorf("absent lexical protected input allowed: %q", cmd)
		}
	}

}
