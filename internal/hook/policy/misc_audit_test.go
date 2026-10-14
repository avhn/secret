package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestMiscAuditPolicy pins dashed Git dispatch, inert environment, and shell stdin.
func TestMiscAuditPolicy(t *testing.T) {
	repo, _, root := isolatedGitFixture(t)
	tracked := filepath.Join(root, "tracked")
	syntheticRepo(t, tracked, 2, "app.env")
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, tc := range []struct {
		name, command string
		deny          bool
	}{
		{"dashed log", "git-log -p", true},
		{"dashed show path", "/usr/lib/git-core/git-show", true},
		{"dashed whatchanged", "git-whatchanged -p", true},
		{"unknown dashed Git", "git-unknown-subcommand", true},
		{"editor vim inline", "EDITOR='vim -c q' git status", true},
		{"editor vim script", "EDITOR='vim -S x.vim' git status", true},
		{"editor emacs eval", "EDITOR='emacs --eval nil' git status", true},
		{"editor code extension", "EDITOR='code --extensionDevelopmentPath ext' git status", true},
		{"pager less key file", "GIT_PAGER='less -k keys.bin' git status", true},
		{"pager less command", "GIT_PAGER='less +q' git status", true},
		{"pager delta config", "GIT_PAGER='delta --config x' git status", true},
		{"editor code wait", "EDITOR='code -w' git status", false},
		{"editor vim", "GIT_EDITOR=vim git status", false},
		{"pager less", "GIT_PAGER='less -FRX' git status", false},
		{"less open", "LESSOPEN=x GIT_PAGER=less git status", true},
		{"less close", "LESSCLOSE=x git status", true},
		{"less key", "LESSKEY=x git status", true},
		{"less key input", "LESSKEYIN=x git status", true},
		{"less unsafe flags", "LESS='FQ' git status", true},
		{"less inert flags", "LESS=FRX git status", false},
		{"pipe sh", "echo 'cat app.env' | sh", true},
		{"pipe bash s", "printf 'cat app.env' | bash -s", true},
		{"pipe bash s args", "printf 'cat app.env' | bash -s -- x", true},
		{"pipe env shell", "echo 'cat app.env' | env -i sh", true},
		{"pipe env split shell", "echo 'cat app.env' | env -S 'sh -s'", true},
		{"pipe busybox shell", "echo 'cat app.env' | busybox sh", true},
		{"pipe timeout shell", "echo 'cat app.env' | timeout 5 sh", true},
		{"pipe nested shell", "echo 'cat app.env' | (sh)", true},
		{"here string protected", "sh <<< 'cat app.env'", true},
		{"here string busybox", "busybox sh -s <<< 'cat app.env'", true},
		{"here string shell args", "bash -s -- x <<< 'cat app.env'", true},
		{"here string timeout shell", "timeout 5 sh <<< 'cat app.env'", true},
		{"quoted here doc protected", "sh <<'EOF'\ncat app.env\nEOF", true},
		{"dynamic here string", "sh <<< \"$SCRIPT\"", true},
		{"file shell input", "bash < safe.txt", true},
		{"here string safe", "sh <<< 'echo ok'", false},
		{"quoted here doc safe", "sh <<'EOF'\necho ok\nEOF", false},
		{"shell inline safe", "bash -c 'npm test'", false},
		{"globstar options", "BASHOPTS=globstar bash -c 'cat app.env'", true},
		{"globstar switch", "bash -O globstar -c 'cat app.env'", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := repo
			if strings.HasPrefix(tc.name, "dashed") || strings.HasPrefix(tc.name, "unknown dashed") {
				dir = tracked
			}
			got := Analyze(tc.command, dir, root, check)
			if (got != "") != tc.deny {
				t.Fatalf("denial=%q, want denied=%t", got, tc.deny)
			}
		})
	}
}
