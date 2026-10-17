package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"mvdan.cc/sh/v3/syntax"
)

// These ten corpus variants preserve the original audit11 denial. The three
// quoted -vd options exposed a Go/Bash split; the other seven are shared Bash
// normalization gaps, not safe commands or reasons to weaken the Go expectation.
func TestAuditElevenNormalizedDenials(t *testing.T) {
	root := t.TempDir()
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct{ name, command string }{
		{"22_single_command", `d=build;'printf' -vd x;echo x > $d/pre-commit`},
		{"22_double_command", `d=build;"printf" -vd x;echo x > $d/pre-commit`},
		{"22_ansi_command", `d=build;$'printf' -vd x;echo x > $d/pre-commit`},
		{"22_single_option", `d=build;printf '-vd' x;echo x > $d/pre-commit`},
		{"22_double_option", `d=build;printf "-vd" x;echo x > $d/pre-commit`},
		{"22_ansi_option", `d=build;printf $'-vd' x;echo x > $d/pre-commit`},
		{"43_command_run0", `echo printenv | command run0 -u root`},
		{"44_command_runuser", `echo printenv | command runuser -u root`},
		{"45_command_runuser_login", `echo printenv | command runuser -l root`},
		{"47_command_pkexec", `echo printenv | command pkexec --user root`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Analyze(tc.command, root, root, check); got == "" {
				t.Fatalf("normalized audit11 denial allowed: %s", tc.command)
			}
		})
	}
}

func TestAuditElevenIndirectStaticAssignments(t *testing.T) {
	root := t.TempDir()
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{`d=build; command printf '-vd' x; echo x > "$d/pre-commit"`, true},
		{`d=build; builtin printf "-v" other x; echo x > $d/pre-commit`, true},
		{`d=build; p'r'intf -vd x; echo x > $d/pre-commit`, true},
		{`d=build; printf -vd x; echo x > $d/pre-commit`, true},
		{`d=build; declare '-n' ref=other; echo x > $d/pre-commit`, true},
		{`d=build; 'declare' '-n' ref=other; echo x > $d/pre-commit`, true},
		{`d=build; "typeset" "-n" ref=other; echo x > $d/pre-commit`, true},
		{`d=build; builtin local $'-n' ref=other; echo x > $d/pre-commit`, true},
		{`d=build; command unset '-n' ref; echo x > $d/pre-commit`, true},
		{`'printf' '-vd' x`, false},
		{`"printf" "-v" ordinary x`, false},
		{`builtin printf $'-vordinary' x`, false},
		{`d=build; printf -- '-vd'; echo x > $d/output.txt`, false},
		{`d=build; printf '%s' '-vd'; echo x > $d/output.txt`, false},
		{`d=build; printf '%s' 'declare -n ref=other'; echo x > $d/output.txt`, false},
		{`d=build; echo 'printf -vd x'; echo x > $d/output.txt`, false},
		{`d=build; printf -vd x; echo x > output.txt`, false},
		{`d=build; 'declare' '-n' ref=other; echo x > output.txt`, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if got := Analyze(tc.command, root, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q, want deny=%v", got, tc.deny)
			}
		})
	}
}

func TestAuditElevenWrappedLauncherStdin(t *testing.T) {
	root := t.TempDir()
	check := func(string, string) bool { return false }
	for _, launcher := range []string{"run0 -u root", "runuser -u root", "runuser -l root", "pkexec --user root"} {
		for _, prefix := range []string{"command ", "command -p ", "builtin ", "builtin -- command ", "command builtin ", "'command' "} {
			command := "echo printenv | " + prefix + launcher
			t.Run(command, func(t *testing.T) {
				if got := Analyze(command, root, root, check); got == "" {
					t.Fatal("wrapped stdin launcher allowed")
				}
			})
		}
	}
	for _, command := range []string{
		"echo text | command cat", "echo text | builtin printf '%s' text",
		"command run0 /bin/true", "command runuser -u root -- /bin/true",
		"command pkexec --user root /bin/true",
	} {
		t.Run(command, func(t *testing.T) {
			if got := Analyze(command, root, root, check); got != "" {
				t.Fatalf("safe wrapper control denied: %s", got)
			}
		})
	}
}

// Query options are not transparent command prefixes. The launcher classifier
// must leave them intact even though the wider policy may deny unmodeled queries.
func TestAuditElevenLauncherQueries(t *testing.T) {
	for _, command := range []string{"command -v run0", "command -V pkexec", "command -v runuser"} {
		t.Run(command, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
			if err != nil {
				t.Fatal(err)
			}
			if launcherStdinStatement(file.Stmts[0]) {
				t.Fatal("command query classified as a stdin launcher")
			}
		})
	}
}

// Future Git directories must retain their protection when cwd flow resolves
// a symlinked root between repository creation and a subsequent write.
func TestAuditElevenFutureGitSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	actual := t.TempDir()
	root := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(actual, root); err != nil {
		t.Fatal(err)
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, command := range []string{
		"git init --bare gd && echo y >> gd/config",
		"git clone --bare https://example.invalid/project gd && echo y >> gd/config",
		"git clone --mirror https://example.invalid/project gd && echo y >> gd/config",
	} {
		t.Run(command, func(t *testing.T) {
			if got := Analyze(command, root, root, check); got == "" {
				t.Fatal("future Git directory write allowed through symlinked cwd")
			}
		})
	}
}

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
		{"git commit -F - <<'EOF'\nfeat: secret exec and cat .env are prose\nEOF", root, false},
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
		{"cat > src/big.ts <<'X'\n" + strings.Repeat("a", 1<<20-4096) + "\nX", root, false},
		{"cat > src/big.ts <<'X'\n" + strings.Repeat("a", 1<<20-4096) + "\nsee .env in docs\nX", root, false},
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
