package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestSixthAuditGitAndShellAssignments(t *testing.T) {
	repo, _, root := isolatedGitFixture(t)
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, command := range []string{
		"git -c core.editor=sh status", "git -c CORE.EDITOR=vi status", "git -c diff.external=sh diff",
		"git -c http.proxy=literal status", "git -c pager.log=less status",
		"git --config-env=core.editor=E status", "E=sh git --config-env=core.editor=E status",
		"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.editor GIT_CONFIG_VALUE_0=sh git status",
		"GIT_CONFIG_PARAMETERS='core.editor=sh' git status",
		"GIT_EDITOR=sh git status", "env GIT_EDITOR=sh git status",
		"export EDITOR=sh; git status", "declare PAGER=python; git status",
		"GIT_EXTERNAL_DIFF=vi git status", "GIT_SSH=vi git status",
		"GIT_SSH_COMMAND=vi git status", "GIT_ASKPASS=vi git status",
		"SSH_ASKPASS=vi git status", "GIT_PROXY_COMMAND=vi git status",
		"GIT_EDITOR='vi; cat app.env' git status", "PAGER='less app.env' git status",
		"GIT_EDITOR='vi\ncat app.env' git status",
		// P13 strict no longer certifies editor or pager arguments outside inert sets.
		"export VISUAL='vim -f'; git status", "export EDITOR='vim -f'; git status",
		"declare PAGER='delta --paging=never'; git status",
	} {
		t.Run(command, func(t *testing.T) {
			if got := Analyze(command, repo, root, check); got == "" {
				t.Fatal("indeterminate assignment allowed")
			}
		})
	}
	for _, command := range []string{
		"git -c color.ui=always status", "git -c pager.log=false status",
		"GIT_EDITOR='code -w' git status", "env PAGER='less -FRX' git status",
		"GIT_EDITOR=vim git status",
	} {
		t.Run(command, func(t *testing.T) {
			if got := Analyze(command, repo, root, check); got != "" {
				t.Fatalf("safe assignment denied: %s", got)
			}
		})
	}
}

func TestSixthAuditShellOptions(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".secrets", "store"), []byte("SYNTHETIC MARKER\n"), 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, command := range []string{
		"BASHOPTS=cdable_vars bash -c 's=.secrets; cd s; paste store'",
		"env BASHOPTS=autocd bash -c 's=.secrets; cd s; paste store'",
		"SHELLOPTS=autocd bash -c 's=.secrets; cd s; paste store'",
		"BASH_ENV=.secrets/store bash -c :", "BASH_ENV=public.sh bash -c :",
	} {
		t.Run(command, func(t *testing.T) {
			if got := Analyze(command, root, root, check); got == "" {
				t.Fatal("child shell option or code allowed")
			}
		})
	}
}

func TestSixthAuditSedGNU(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNU sed runtime evidence runs on Linux")
	}
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip("GNU sed unavailable")
	}
	root := t.TempDir()
	for file, text := range map[string]string{"in.txt": "x\n", "app.env": "SYNTHETIC MARKER\n"} {
		if err := os.WriteFile(filepath.Join(root, file), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	t.Run("newline substitution delimiter", func(t *testing.T) {
		script := "s\nx\ny\n;r app.env"
		cmd := exec.Command("sed", "-n", script, "in.txt")
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err == nil || strings.Contains(string(output), "SYNTHETIC MARKER") {
			t.Fatalf("GNU sed accepted newline delimiter: %v %q", err, output)
		}
		if got := AnalyzeArgv([]string{"sed", "-n", script, "in.txt"}, root, root, check); got == "" {
			t.Fatal("unparseable newline delimiter allowed")
		}
	})
	t.Run("substitution write", func(t *testing.T) {
		out := filepath.Join(root, "written.env")
		cmd := exec.Command("sed", "-n", "s|x|SYNTHETIC MARKER|w "+out, "in.txt")
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("GNU sed failed to write marker: %v %q", err, output)
		}
		data, err := os.ReadFile(out)
		if err != nil || !strings.Contains(string(data), "SYNTHETIC MARKER") {
			t.Fatalf("GNU sed did not write marker: %v %q", err, data)
		}
		if got := AnalyzeArgv([]string{"sed", "-n", "s|x|SYNTHETIC MARKER|w " + out, "in.txt"}, root, root, check); got == "" {
			t.Fatal("substitution write to protected marker allowed")
		}
	})
	for _, script := range []string{"#n; r app.env", "a text; r app.env"} {
		t.Run("text or comment "+script, func(t *testing.T) {
			cmd := exec.Command("sed", "-n", script, "in.txt")
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil || strings.Contains(string(out), "SYNTHETIC MARKER") {
				t.Fatalf("GNU sed unexpectedly ran comment or text as code: %v %q", err, out)
			}
			// Literal protected names in sed text still conservatively deny.
		})
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"brace and separator", []string{"-n", "{s/x/y/;r app.env\n}"}},
		{"one-line text", []string{"-n", "a text\nr app.env"}},
		{"continued text", []string{"-n", "a\\\ntext\nr app.env"}},
		{"even backslashes end text", []string{"-n", "a text\\\\\nr app.env"}},
		{"odd backslashes continue text", []string{"-n", "a text\\\\\\\nmore text\nr app.env"}},
		{"first-line comment", []string{"-n", "#n\nr app.env"}},
		{"label separator", []string{"-n", ":a;r app.env"}},
		{"escaped delimiter", []string{"-n", `s#x#\##;r app.env`}},
		{"bracket delimiter", []string{"-n", `s#[x]#y#;r app.env`}},
		{"transliteration", []string{"-n", "y|x|y|;r app.env"}},
		{"substitution execution", []string{"-n", "s|x|cat app.env|ep"}},
		{"null data", []string{"-nz", "r app.env"}},
		{"extended regex", []string{"-nE", "s/(x)/y/;r app.env"}},
		{"separate files", []string{"-ns", "r app.env"}},
		{"posix", []string{"-n", "--posix", "r app.env"}},
		{"multiple expressions", []string{"-n", "-e", "s/x/y/", "-e", "r app.env"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, tc.args...), "in.txt")
			cmd := exec.Command("sed", args...)
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "SYNTHETIC MARKER") {
				t.Fatalf("GNU sed did not execute marker: %v %q", err, out)
			}
			// AnalyzeArgv preserves scripts exactly, including their embedded newlines.
			if got := AnalyzeArgv(append([]string{"sed"}, args...), root, root, check); got == "" {
				t.Fatal("GNU sed marker read allowed")
			}
			if tc.name == "even backslashes end text" {
				a := &analyzer{cwd: root, home: root, protected: check}
				a.parseSedScript(tc.args[1], 0, root)
				if a.reason == "" {
					t.Fatal("sed grammar swallowed command after even backslashes")
				}
			}
		})
	}
}
