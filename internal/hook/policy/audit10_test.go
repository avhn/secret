package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestAuditTenAddendum keeps the new denials and common read/write forms paired.
// Command strings are parsed by the hook; none is executed.
func TestAuditTenAddendum(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	syntheticRepo(t, root, 2, "src/safe.go")
	if err := os.WriteFile(filepath.Join(root, "app.env"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	gd := filepath.Join(root, "gd")
	work := filepath.Join(root, "work")
	cases := []struct {
		source string
		deny   bool
	}{
		{"bash -c - 'cat app.env'", true}, {"sh -c - 'cat app.env'", true},
		{"bash -xc - 'cat app.env'", true}, {"env bash -c - 'cat app.env'", true},
		{"sudo bash -c - 'cat app.env'", true}, {"coproc bash -c - 'cat app.env'", true},
		{"bash -c - 'echo x >> .git/config'", true},
		{"cp -ft.git /tmp/e/config", true}, {"cp -rt.git a", true},
		{"mv -ft.git a", true}, {"install -Dt.git a", true},
		{"ln -sft.git a", true}, {"ln -sfnt.git a", true},
		{"doas -s <<< 'cat app.env'", true}, {"run0 <<< 'cat app.env'", true},
		{"pkexec <<< 'cat app.env'", true}, {"sudo", true}, {"echo x | sudo", true}, {"expect <<< 'cat app.env'", true},
		{"expect - <<< 'cat app.env'", true},
		{fmt.Sprintf("GIT_DIR='%s/'; echo x > '%s/config'", gd, gd), true},
		{fmt.Sprintf("GIT_DIR='%s/./gd'; echo x > '%s/config'", root, gd), true},
		{fmt.Sprintf("GIT_DIR='%s//'; echo x > '%s/config'", gd, gd), true},
		{fmt.Sprintf("GIT_DIR='%s'; echo x > '%s//config'", gd, gd), true},
		{fmt.Sprintf("git --git-dir='%s' status; echo x > '%s/config'", gd, gd), true},
		{fmt.Sprintf("git --git-dir '%s' init; echo x > '%s/hooks/pre-commit'", gd, gd), true},
		{fmt.Sprintf("GIT_COMMON_DIR='%s'; echo x > '%s/config'", gd, gd), true},
		{fmt.Sprintf("git init --separate-git-dir='%s'; echo x > '%s/config'", gd, gd), true},
		{fmt.Sprintf("git --work-tree='%s' status; echo x > '%s/.git/config'", work, work), true},
		{`python3 -c 'open(".git/config","a")'`, true},
		{`node -e 'require("fs").appendFileSync(".git/config","x")'`, true},
		{`ruby -e 'File.write(".git/hooks/pre-commit","x")'`, true},
		{`perl -e 'open F,">>.git/config"'`, true},
		{"tar --directory=.git -xf a.tar", true}, {"tar -xf a.tar -C.git", true},
		{"tar --one-top-level=.git -xf a.tar", true}, {"unzip -d.git a.zip", true},
		{"7z x a.7z -o.git", true}, {"cp --target=.git a", true},
		{"git submodule --quiet foreach ls", true}, {"git submodule -q foreach ls", true},
		{"echo x >> ~someuser/.gitconfig", true},
		{"ls | xargs -n1 echo", true}, {"git apply p.diff", true},
		{"git apply --check app.env", true},
		{"unknown --cmd='cat app.env'", true},
		{"docker --command='cat app.*'", true},
		{"npm exec -c 'cat app.env'", true}, {"make --eval='cat app.env'", true},
		{"make -f /dev/null", true}, {"rsync -e 'cat app.env' a b", true},
		{"op run -- cat app.env", true}, {"gh alias set x '!cat app.env'", true},
		{"flock -c '{cat,app.*}'", true}, {"watch '{cat,app.*}'", true},
		{"su -c '{cat,app.*}'", true}, {"./bash-static -c 'cat app.env'", true},
		{"busybox sh -c 'cat app.env'", true},
		{"DEST=out.txt; read DEST; echo x > $DEST", true},
		{"DEST=out.txt; for DEST in foo; do :; done; echo x > $DEST", true},
		{"DEST=out.txt; printf -v DEST x; echo x > $DEST", true},
		{"DEST=out.txt; mapfile DEST; echo x > $DEST", true},
		{"DEST=out.txt; declare DEST; echo x > $DEST", true},
		{"DEST=out.txt; DEST+=x; echo x > $DEST", true},
		{"DEST=out.txt command true; echo x > $DEST", true},
		{"read HOME; echo x > $HOME/output.txt", true},
		{"read XDG_CONFIG_HOME; echo x > $XDG_CONFIG_HOME/other.txt", true},
		{"find . -fprintf out.txt '%p'", true}, {"find . -fprint0 out.txt", true},
		{"find . -fls out.txt", true},
		{"cat .gitignore", false}, {"echo x >> .gitignore", false},
		{"cp a .github/workflows/b.yml", false}, {"sed -i 's/a/b/' .gitattributes", false},
		{"git status", false}, {"git add .", false},
		{"git commit -m 'update .git docs'", false}, {"git push", false},
		{"python3 -c 'print(1)'", false}, {"node -e 'console.log(1)'", false},
		{"bash -c 'npm test'", false}, {"sudo apt-get install -y jq", false},
		{"tar -xf a.tar -C build", false}, {"cp -t dist a b", false},
		{"ls .git", false}, {"rg foo .git", false},
		{"xargs -n1 echo", false}, {"git apply --check p.diff", false},
		{"git apply --stat p.diff", false}, {"git apply --numstat p.diff", false},
		{"gh pr create --title 'fix(api): handle null'", false},
		{`gh issue comment 1 --body "don't do that"`, false},
		{`curl -d '{"a": 1}' https://x/y`, false},
		{"psql -c 'select 1'", false}, {"kubectl get pods -l 'app in (a,b)'", false},
		{"gh api r --jq '.[] | .title'", false},
		{"kill -9 $(pgrep node)", false}, {"sqlite3 db 'select * from t'", false},
		{"npx eslint 'src/**/*.ts'", false}, {"kubectl set image d x=y", false},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			if reason := Analyze(tc.source, root, home, check); (reason != "") != tc.deny {
				t.Errorf("denial=%q, want denial=%v", reason, tc.deny)
			}
		})
	}
}

// TestBoundedTokens matches the shell guard's 256-word analysis boundary.
func TestBoundedTokens(t *testing.T) {
	root := t.TempDir()
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		name, source string
		deny         bool
	}{
		{"under limit", "echo " + strings.Repeat("word ", 130) + ".ENV", false},
		{"over limit", "echo " + strings.Repeat("word ", 260) + ".ENV", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := Analyze(tc.source, root, root, check); (reason != "") != tc.deny {
				t.Errorf("denial=%q, want denial=%v", reason, tc.deny)
			}
		})
	}
}
