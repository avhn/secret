package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestHookAddenda(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env", ".gitmodules", "in"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "README.md")
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	cases := []struct {
		cmd  string
		deny bool
	}{
		{"sed -i 's/a/b/g' in", false}, {"sed -n '1,5p' in", false}, {"sed '/x/d' in", false},
		{`sed ':a;N;$!ba;s/\n/ /g' in`, false}, {"sed '$a text' in", false},
		{"bash -c 'npm test'", false}, {"git status", false}, {"git log --oneline", false},
		{"EDITOR='code -w' git commit -m x", false},
		{"FOO+=bar echo ok", false}, {"bash -o errexit -c 'npm test'", false},
		{"busybox hush -c 'npm test'", false}, {"script -qc \"sh -c 'npm test'\"", false},
		{"sudo -s 'cat in'", true}, {"sudo -s 'cat .env'", true}, {"sh in", false}, {"sh /dev/stdin", true}, {"bash missing.sh", true},
		{"sed ':a s/x/touch PROBE/e' in", true}, {"sed 't a s/x/touch PROBE/e;:a' in", true},
		{"sed 'e :;cd .;cat .env' in", true}, {"sed -e 'e :\\' -e 'cat .env' in", true},
		{`sed 'e echo \;cat .env' in`, true}, {"sed 's/x/cat .env/e' in", true},
		{"sed 'w d;cd/../.git/config' in", true}, {"sed 's/x/y/e' in -e p", true},
		{"POSIXLY_CORRECT=1 sed p in", true}, {"env POSIXLY_CORRECT=1 sed p in", true},
		{"sed 's/x/y/w out' in", true}, {"sed 'F' in", true},
		{"sed 'a\\\np' in", true}, {"sed 'v 4.2 s/x/y/e' in", true},
		{`sed -n -e '\%q' -e 's/x/touch PROBE/e;#%p' in`, true},
		{"cat .env |& sh", true}, {"bash -o errexit", true}, {"bash --rcfile in", true},
		{"sh <<<'echo ok'", true}, {"sh <<'EOF'\necho ok\nEOF", true},
		{"source /dev/stdin", true}, {"setsid sh", true}, {"script -qc sh", true},
		{"busybox hush", true}, {"toybox msh", true}, {"busybox hush -c 'cat .env'", true},
		{"LESSKEY_CONTENT=x git status", true}, {"LESS+=R git status", true},
		{"GIT -C . grep -R token", true}, {"SED 's/x/y/e' in", true},
		{"git config core.fsmonitor x", true}, {"echo x > .git/config", true},
		{"echo x > .gitmodules", true}, {"tee .git/config", true},
		{"cp in .git/config", true}, {"dd if=in of=.git/config", true},
		{"sed -i 's/x/y/' .git/config", true}, {"touch .git/config", true},
		{"echo x > ~/.gitconfig", true}, {"GIT_CONFIG_GLOBAL=custom echo x > custom", true},
		{"bash --rcfile .env -c 'npm test'", true}, {"fish -C 'cat .env' -c 'echo ok'", true},
		{"LESSKEY_CONTENT+=x git status", true}, {"env LESSOPEN+=x git status", true},
		{"git diff --submodule=diff", true}, {"git grep --recurse-submodules token", true},
		{"./git-log --patch .env", true}, {"git-grep token .env", true},
		{"PATH=/tmp git-log --patch", true},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			reason := Analyze(tc.cmd, root, root, check)
			if (reason != "") != tc.deny {
				t.Errorf("denial=%q want deny=%t", reason, tc.deny)
			}
		})
	}
}

func TestConfigWriteSymlink(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2, "README.md")
	config := filepath.Join(root, ".git", "config")
	if err := os.WriteFile(config, []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "config-alias")
	if err := os.Symlink(config, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, source := range []string{"echo synthetic > config-alias", "tee config-alias", "sed -i 's/a/b/' config-alias"} {
		if reason := Analyze(source, root, root, check); reason == "" {
			t.Errorf("Git configuration alias allowed: %s", source)
		}
	}
}

func TestWorktreeGitdirWrite(t *testing.T) {
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	gitdir := filepath.Join(root, "worktree-gitdir")
	for _, dir := range []string{worktree, gitdir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitdir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	cmd := "touch '" + filepath.Join(gitdir, "config") + "'"
	if reason := Analyze(cmd, worktree, root, check); reason == "" {
		t.Fatalf("gitfile target write allowed: %s", cmd)
	}
}
