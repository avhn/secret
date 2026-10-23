package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestAuditNineGuardParity pins the four command forms found by the guard suite.
func TestAuditNineGuardParity(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2, "src/f")
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, tc := range []struct {
		name, source, cwd string
		deny              bool
	}{
		{"xargs stdin in repo", "xargs -n1 echo", root, false},
		{"xargs stdin outside repo", "xargs -n1 echo", t.TempDir(), false},
		{"xargs file reader", "xargs -n1 cat", root, true},
		{"quoted printer argument", `gh auth token ">" | secret stash a K`, root, false},
		{"unmodelled shell text", `ssh host "cat .env"`, root, true},
		{"coproc script redirect", "coproc sh < s.sh", root, true},
		{"patch without output", "patch < changes.patch", root, true},
		// An output target does not certify the files selected by diff headers.
		{"patch with opaque input and output", "patch -o output.txt < changes.patch", root, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := Analyze(tc.source, tc.cwd, root, check)
			if (reason != "") != tc.deny {
				t.Errorf("denial=%q, want denial=%v", reason, tc.deny)
			}
		})
	}
}

func TestNinthAuditAndCommonForms(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2, "src/f")
	for _, name := range []string{".git/config", "src/f", "src/existing.ts"} {
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	deny := []string{
		"sed -Ei 's/a/b/' .git/config", "sed -ni 's/a/b/' .git/config", "sed --in 's/a/b/' .git/config", "perl -pi -e 's/a/b/' .git/config", "perl -pi -e 's/a/b/' ~/.gitconfig",
		"patch .git/config", "patch -o .git/config src/f", "tar -C .git -xf archive.tar", "tar --directory .git -xf archive.tar", "mkdir -p .git/hooks", "cp -t.git src/f", "echo x &>> .git/config", fmt.Sprintf("GIT_DIR='%s'; touch '%s/config'", filepath.Join(root, "gd"), filepath.Join(root, "gd")), "sudo VAR=1 sh < src/f",
		"git submodule foreach echo", "git submodule foreach 'npm test'", "echo x > *.txt", "echo x > $UNSET", "pushd elsewhere; echo x > output.txt", "cd -; touch output.txt", "touch *.txt", "touch *.ts", "tee $UNSET", "cp src/f $UNSET", "patch .git/config", "sed -n '1,5p' .git/config", "ssh host 'cat .env'", "sudo -i", "sudo -s", "su", "su -c 'cat .env'", "coproc { cat .env; }",
		"bash5 -c 'cat .env'", "sh5 -c 'cat .env'", "bash-5.2 -c 'cat .env'", "bash -c -- 'cat .env'", "bash -c -x 'cat .env'", "bash -oc posix 'cat .env'", "bash -co posix 'cat .env'", "bash -Oc extglob -c 'cat .env'", "bash -c -o posix 'cat .env'", "bash -c --norc 'cat .env'", "fish -c true -C 'cat .env'", "fish --init-command='cat .env' -c true", "coproc sh", "coproc cat .env",
	}
	for _, wrapper := range []string{"unshare", "flock", "chrt", "taskset", "ionice", "chroot", "nsenter", "doas", "run0", "pkexec", "systemd-run", "firejail", "rlwrap", "strace", "fakeroot", "bwrap", "runuser", "su", "watch", "tmux", "expect"} {
		deny = append(deny, wrapper+" sh -c 'cat .env'")
	}
	allow := []string{
		"git status", "git log --oneline", "git diff --stat", "git add src/f", "git commit -m ok", "git push", "git pull", "git stash", "git commit -m 'cat .env mention'",
		"sed -i 's/a/b/' src/f", "sed -n '1,5p' src/f", "bash -c 'npm test'", "bash -oc posix 'npm test'", "bash -co posix 'npm test'", "bash -Oc extglob -c true", "sh -c 'make'", "npm test", "go test ./...", "rg TODO src", "echo x > out.txt", `for f in *.ts; do echo "$f"; done`, "docker run img ls", "ssh host uptime", "timeout 5 npm test", "xargs -n1 echo", "cat .git/config", "git submodule status", "DEST=src/new.ts; echo x > $DEST", "echo x > $HOME/other.txt",
	}
	for _, tc := range append(deny, allow...) {
		t.Run(tc, func(t *testing.T) {
			reason := Analyze(tc, root, root, check)
			expected := true
			for _, safe := range allow {
				if safe == tc {
					expected = false
					break
				}
			}
			if (reason != "") != expected {
				t.Errorf("denial=%q, want denial=%v", reason, expected)
			}
		})
	}
	if reason := AnalyzeArgv([]string{"bash", "-c", "--", "cat .env"}, root, root, check); reason == "" {
		t.Error("argv shell bypass")
	}
	// A static write destination remains valid in a normal working directory.
	if reason := Analyze("echo x > src/new.ts", root, root, check); reason != "" {
		t.Errorf("ordinary write denied: %s", reason)
	}
}
