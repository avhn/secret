package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func audit20StdinFixture(t *testing.T) (string, string, func(string, string) bool) {
	t.Helper()
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{home, work, filepath.Join(home, ".kube")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(work, "custom.cfg"), filepath.Join(work, "README.md"), filepath.Join(home, ".kube", "config")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	return home, work, func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
}

// Commands below are analyzer inputs only. No producer, interpreter or probe is
// executed; the only repository data is fabricated index names and metadata.
func TestAudit20InterpreterStdinRecipients(t *testing.T) {
	home, work, check := audit20StdinFixture(t)
	for _, command := range []string{"python3", "node", "ruby", "perl"} {
		for _, recipient := range []struct{ prefix, command string }{
			{"", command},
			{"", "env " + command},
			{"", "env -i -- " + command},
			{"", "timeout 5 " + command},
			{"", "command env timeout -s TERM 5 " + command},
			{"", "nice -n 5 " + command},
			{"", "stdbuf -oL " + command},
			{"", "nohup " + command},
			{"", "exec " + command},
			{"", "(" + command + ")"},
			{"", "{ " + command + "; }"},
			{"", "{ true; (env " + command + "); }"},
			{"alias p='" + command + "'\n", "p"},
			{"alias p='env " + command + "'\n", "p"},
			{"alias p='(" + command + ")'\n", "p"},
			{"alias p=next\nalias next='" + command + "'\n", "p"},
		} {
			for _, name := range []string{"custom.cfg", "./custom.cfg", "README.md"} {
				body := `print(open("` + name + `").read())`
				for _, producer := range []string{"printf '%s' '" + body + "'", `printf '%s' "` + strings.ReplaceAll(body, `"`, `\"`) + `"`, "cat <<< '" + body + "'"} {
					source := "KUBECONFIG=custom.cfg;\n" + recipient.prefix + producer + " | " + recipient.command
					if reason := Analyze(source, work, home, check); (reason != "") != (name != "README.md") {
						t.Errorf("%s: reason=%q", source, reason)
					}
				}
			}
		}
	}
	for _, source := range []string{
		`printf '%s' 'open("custom.cfg")' | env KUBECONFIG=custom.cfg python3`,
		`printf '%s' 'open("config")' | (cd ~/.kube; python3)`,
		`printf '%s' 'open("config")' | env -C ~/.kube python3`,
		`printf '%s' 'open("custom.cfg")' | (KUBECONFIG=custom.cfg; python3)`,
		"KUBECONFIG='" + filepath.ToSlash(filepath.Join(work, "custom.cfg")) + "'; " + `printf '%s' "open('$PWD/custom.cfg')" | env -C .. python3`,
		"KUBECONFIG='" + filepath.ToSlash(filepath.Join(work, "custom.cfg")) + "'; " + `env -C .. python3 <<< "open('$PWD/custom.cfg')"`,
		"KUBECONFIG=custom.cfg; F=custom.cfg; cat <<BODY | env python3\nopen('$F')\nBODY",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("recipient config/cwd lost upstream source: %s", source)
		}
	}
	// The pending pipe source must not escape into a later independent command.
	if reason := Analyze(`KUBECONFIG=custom.cfg; printf '%s' 'open("custom.cfg")' | cat >/dev/null; python3 -c 'print("public")'`, work, home, check); reason != "" {
		t.Errorf("pipe source escaped its recipient: %s", reason)
	}
}

func TestAudit20ExpandedInterpreterStdin(t *testing.T) {
	home, work, check := audit20StdinFixture(t)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, recipient := range []string{"python3", "env python3", "timeout 5 python3", "(python3)", "{ python3; }"} {
			for _, tc := range []struct {
				body string
				deny bool
			}{
				{`print(open('$F').read())`, true},
				{`print(open('./${F}').read())`, true},
				{`print(open('$PUBLIC').read())`, false},
				{`print(open('$UNKNOWN').read())`, true},
				{`print(open('$(unresolved)').read())`, true},
				{`print(open('${F:-README.md}').read())`, true},
			} {
				prefix := key + "=custom.cfg; F=custom.cfg; PUBLIC=README.md; "
				for _, stdin := range []string{" <<< \"" + tc.body + "\"", " <<BODY\n" + tc.body + "\nBODY"} {
					source := prefix + recipient + stdin
					if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
						t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
					}
				}
			}
		}
	}
	for _, delimiter := range []string{"'BODY'", `"BODY"`, `\BODY`} {
		for _, body := range []string{`print(open('$F').read())`, `print('$UNKNOWN')`, `print('$(unresolved)')`} {
			source := "KUBECONFIG=custom.cfg; F=custom.cfg; python3 <<" + delimiter + "\n" + body + "\nBODY"
			if reason := Analyze(source, work, home, check); reason != "" {
				t.Errorf("quoted heredoc expanded: %s: %s", source, reason)
			}
		}
	}
	for _, source := range []string{
		`KUBECONFIG=custom.cfg; python3 <<< 'print("$UNKNOWN")'`,
		`F=README.md; python3 <<< "print(open('$F').read())"`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("literal/public stdin denied: %s: %s", source, reason)
		}
	}
}

func TestAudit20LongInterpreterText(t *testing.T) {
	home, work, check := audit20StdinFixture(t)
	for _, tc := range []struct {
		text string
		deny bool
	}{
		{strings.Repeat("hello world ", 30), false},
		{strings.Repeat("x", 300), false},
		{strings.Repeat("public ", 50) + "/.aws/credentials", true},
		{strings.Repeat("public ", 50) + "/.env", true},
	} {
		body := `print("` + tc.text + `")`
		for _, source := range []string{
			"python3 -c '" + body + "'",
			"python3 <<'BODY'\n" + body + "\nBODY",
			"python3 <<< '" + body + "'",
			"printf '%s' '" + body + "' | python3",
			`printf '%s' "` + strings.ReplaceAll(body, `"`, `\"`) + `" | env python3`,
		} {
			if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("long literal: %s: reason=%q, deny=%v", source, reason, tc.deny)
			}
		}
	}
	// Even an impossible filename remains a witness if explicitly configured.
	long := strings.Repeat("public ", 50)
	t.Setenv("KUBECONFIG", filepath.Join(work, long))
	if reason := Analyze("python3 -c 'open(\""+long+"\")'", work, home, check); reason == "" {
		t.Error("long configured filename lost protection")
	}
	// Metadata errors for plausible paths must still deny.
	if runtime.GOOS != "windows" {
		if err := os.Symlink("loop", filepath.Join(work, "loop")); err != nil {
			t.Fatal(err)
		}
		if reason := Analyze(`python3 -c 'open("loop")'`, work, home, check); reason == "" {
			t.Error("plausible symlink-loop path allowed")
		}
	}
}

func TestAudit20InheritedAWSIndex(t *testing.T) {
	home, work, check := audit20StdinFixture(t)
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, configured := range []string{"custom.cfg", "custom:config.cfg"} {
			if runtime.GOOS == "windows" && strings.Contains(configured, ":") {
				continue // A colon is not a Windows filename component.
			}
			t.Setenv(key, filepath.Join(work, configured))
			for _, version := range []uint32{2, 3, 4} {
				for _, staged := range []string{configured, "README.md"} {
					syntheticRepo(t, work, version, staged)
					for _, command := range []string{"git diff --cached", "git diff --staged", "git show"} {
						if reason := Analyze(command, work, home, check); (reason != "") != (staged == configured) {
							t.Errorf("%s=%s index v%d %s %s: reason=%q", key, configured, version, staged, command, reason)
						}
					}
				}
			}
		}
		t.Setenv(key, "")
	}
}
