package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// These are shell source strings, not commands to execute.
func TestP18Revised(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"src", "sub", "sepgd"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"objects", "refs"} {
		if err := os.Mkdir(filepath.Join(root, "sepgd", dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "sepgd", "HEAD"), []byte("ref: refs/heads/main\n"), 0600); err != nil {
		t.Fatal(err)
	}
	protected := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	cases := []struct {
		name, source string
		deny         bool
	}{
		{"python heredoc", "python3 <<'EOF'\nprint(open('.env').read())\nEOF", true},
		{"node heredoc", "node <<'EOF'\nfs.readFileSync('.env')\nEOF", true},
		{"perl heredoc", "perl <<'EOF'\nopen F, '.env';\nEOF", true},
		{"ruby heredoc", "ruby <<'EOF'\nFile.write('.git/config','x')\nEOF", true},
		{"python here string", `python3 <<<'open(".git/config","w")'`, true},
		{"unknown quoted", `foo "load .npmrc"`, true},
		{"unknown attached", `foo --x='cat .env'`, true},
		{"unknown malformed git", `foo '.git/config`, true},
		{"git stdin message body", "git commit -F - <<'EOF'\nfeat: cat .env is prose\nEOF", true},
		{"tab stripped cat body", "cat <<-EOF\n\tsecret exec x\n\tEOF", false},
		{"separate gitdir inline", `python3 -c 'open("../sepgd/config","w")'`, true},
		{"inline python token", `python3 -c 'print(".npmrc")'`, true},
		{"inline node token", `node --eval='console.log(".pypirc")'`, true},
		{"inline php token", `php -r 'echo "service.secret";'`, true},
		{"strict command slot", `flock -c 'echo .npmrc'`, true},
		{"strict separate gitdir", `flock -c 'echo "../sepgd/config"'`, true},
		{"sudo shell cluster", `sudo -s 'cat src/a.ts'`, true},
		{"secret show", `secret show .env`, false},
		{"secret run", `secret run -f .env -- npm test`, false},
		{"secret home run", `secret run -f ~/.secrets/app.env -- npm test`, false},
		{"secret stash", `secret stash .env K`, false},
		{"docker env file", `docker run --env-file .env img`, false},
		{"node env file", `node --env-file=.env app.js`, false},
		{"dotenv env file", `dotenv -e .env -- npm test`, false},
		{"ls metadata", `ls -la .env`, false},
		{"rm metadata", `rm .env`, false},
		{"chmod metadata", `chmod 600 .env`, false},
		{"git check-ignore", `git check-ignore .env`, false},
		{"copy output", `cp src/a.ts .env`, false},
		{"git message", `git commit -m 'drop .env from docs'`, false},
		{"gh body", `gh pr create --title t --body 'never commit .env'`, false},
		{"echo redirected", `echo 'see .git/config' > notes.md`, false},
		{"printf literal", `printf '%s\n' .env.example`, false},
		{"rg pattern", `rg -n '.env' src`, false},
		{"cat heredoc", "cat > notes.md <<'EOF'\n.env\nEOF", false},
		{"cat stdout heredoc", "cat <<'EOF'\n.env\nEOF", true},
		{"tee heredoc", "tee notes.md <<'EOF'\n.env\nEOF", false},
		{"cat protected output", "cat > .env <<'EOF'\n.env\nEOF", true},
		{"tee here string safe", `tee notes.md <<<'see .env'`, false},
		{"tee here string protected", `tee .env <<<'see .env'`, true},
		{"commit heredoc substitution", "git commit -m \"$(cat <<'EOF'\nmsg\nEOF\n)\"", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cwd := root
			if tc.name == "separate gitdir inline" || tc.name == "strict separate gitdir" {
				cwd = filepath.Join(root, "sub")
			}
			if reason := Analyze(tc.source, cwd, home, protected); (reason != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", reason, tc.deny)
			}
		})
	}
	for _, tc := range []struct {
		argv []string
		deny bool
	}{
		{[]string{"foo", "load .npmrc"}, true},
		{[]string{"foo", "--x=cat .env"}, true},
		{[]string{"secret", "show", ".env"}, false},
		{[]string{"node", "--env-file=.env", "app.js"}, false},
	} {
		if reason := AnalyzeArgv(tc.argv, root, home, protected); (reason != "") != tc.deny {
			t.Errorf("argv %q denial=%q want deny=%v", tc.argv, reason, tc.deny)
		}
	}
}
