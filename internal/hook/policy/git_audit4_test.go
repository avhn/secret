package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// isolatedGitFixture creates only synthetic index names and Git config text.
func isolatedGitFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdg")
	for _, dir := range []string{home, filepath.Join(xdg, "git")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for key, val := range map[string]string{
		"HOME": home, "XDG_CONFIG_HOME": xdg,
		"GIT_CONFIG_SYSTEM": filepath.Join(root, "missing-system"), "GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_COUNT": "0",
	} {
		t.Setenv(key, val)
	}
	for _, key := range []string{"GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_DIR", "GIT_WORK_TREE", "GIT_EXEC_PATH"} {
		t.Setenv(key, "") // Register restoration before removing inherited injection.
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
	repo := filepath.Join(root, "ca")
	dir := syntheticRepo(t, repo, 2, "safe.go")
	if err := os.WriteFile(filepath.Join(repo, ".env"), []byte("SYNTHETIC_ONLY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return repo, dir, root
}

// TestGitFourthAuditReproducers pins every Go-only audit envelope to a
// fabricated repository; no Git process or object data participates.
func TestGitFourthAuditReproducers(t *testing.T) {
	cases := []struct {
		name, local, global, xdg, include, command, envKey, envValue string
		missing, bare                                                bool
	}{
		{name: "GO-1 chained alias", local: "[alias]\n a = b\n b = !cat .env\n", command: "git a"},
		{name: "GO-1 global alias", global: "[alias]\n h = !cat .env\n", command: "git h"},
		{name: "GO-1 XDG alias", xdg: "[alias]\n xg = !cat .env\n", command: "git xg"},
		{name: "GO-1 included alias", local: "[include]\n path = ../../included.cfg\n", include: "[alias]\n i = !cat .env\n", command: "git i"},
		{name: "GO-2 quoted shell alias", local: "[alias]\n q = \"!cat .env\"\n", command: "git q"},
		{name: "GO-3 remote uploadpack", command: "git -c remote.x.url=unused -c 'remote.x.uploadpack=cat .env; git-upload-pack' fetch x"},
		{name: "GO-3 ext clone", command: "git -c protocol.ext.allow=always clone ext::cat destination"},
		{name: "GO-3 URL rewrite", command: "git -c url.ext::sh.insteadOf=zz -c protocol.ext.allow=always fetch zz"},
		{name: "GO-3 core proxy", command: "git -c 'core.gitProxy=cat .env' fetch origin"},
		{name: "GO-3 receivepack", command: "git -c 'remote.x.receivepack=cat .env' push x"},
		{name: "GO-4 bare log", bare: true, command: "git log -p"},
		{name: "GO-4 bare show", bare: true, command: "git show HEAD"},
		{name: "GO-4 no index", missing: true, command: "git log -p"},
		{name: "GO-5 object directory", envKey: "GIT_OBJECT_DIRECTORY", envValue: "objects", command: "git cat-file -p abcdef"},
		{name: "GO-5 alternates", envKey: "GIT_ALTERNATE_OBJECT_DIRECTORIES", envValue: "objects", command: "git cat-file -p abcdef"},
		{name: "P1c namespace", envKey: "GIT_NAMESPACE", envValue: "other", command: "git log -p"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, dir, root := isolatedGitFixture(t)
			write := func(file, text string) {
				t.Helper()
				if text != "" {
					if err := os.WriteFile(file, []byte(text), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			write(filepath.Join(dir, "config"), tc.local)
			write(filepath.Join(root, "included.cfg"), tc.include)
			write(filepath.Join(root, "home", ".gitconfig"), tc.global)
			write(filepath.Join(root, "xdg", "git", "config"), tc.xdg)
			if tc.global != "" {
				t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(root, "home", ".gitconfig"))
			}
			if tc.envKey != "" {
				t.Setenv(tc.envKey, filepath.Join(root, tc.envValue))
			}
			if tc.missing {
				if err := os.Remove(filepath.Join(dir, "index")); err != nil {
					t.Fatal(err)
				}
			}
			if tc.bare {
				repo = filepath.Join(root, "bare.git")
				if err := os.MkdirAll(filepath.Join(repo, "objects"), 0700); err != nil {
					t.Fatal(err)
				}
				write(filepath.Join(repo, "HEAD"), "ref: refs/heads/synthetic\n")
			}
			check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
			if reason := Analyze(tc.command, repo, filepath.Join(root, "home"), check); reason == "" {
				t.Fatal("shell command allowed")
			}
			if reason := AnalyzeArgv([]string{"sh", "-c", tc.command}, repo, filepath.Join(root, "home"), check); reason == "" {
				t.Fatal("argv shell command allowed")
			}
		})
	}
}

// TestGitConfigInjectionAndInheritedEnvironment verifies the inline allowlist
// and that inherited editors are never parsed as command text.
func TestGitConfigInjectionAndInheritedEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, command, key, val string
		deny                    bool
	}{
		{name: "inert", command: "git -c color.ui=always status"},
		{name: "unknown literal", command: "git -c example.option=literal status", deny: true},
		{name: "url rewrite", command: "git -c url.ext::sh.insteadOf=zz status", deny: true},
		{name: "protocol ext", command: "git -c protocol.ext.allow=always status", deny: true},
		{name: "numbered config", command: "git status", key: "protocol.ext.allow", val: "always", deny: true},
		{name: "config env", command: "git --config-env=protocol.ext.allow=INJECTED status", key: "INJECTED", val: "always", deny: true},
		{name: "inherited pager", command: "git status", key: "PAGER", val: "less -FRX"},
		{name: "inherited editor", command: "git status", key: "EDITOR", val: "code -w"},
		{name: "inline pager", command: "GIT_PAGER='less -FRX' git status"},
		{name: "inline editor", command: "EDITOR='code -w' git status"},
		{name: "inline reader", command: "GIT_PAGER='cat .env' git status", deny: true},
		{name: "inline object override", command: "GIT_OBJECT_DIRECTORY=objects git log -p", deny: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, _, root := isolatedGitFixture(t)
			if tc.name == "numbered config" {
				t.Setenv("GIT_CONFIG_COUNT", "1")
				t.Setenv("GIT_CONFIG_KEY_0", tc.key)
				t.Setenv("GIT_CONFIG_VALUE_0", tc.val)
			} else if tc.key != "" {
				t.Setenv(tc.key, tc.val)
			}
			check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
			if reason := Analyze(tc.command, repo, filepath.Join(root, "home"), check); (reason != "") != tc.deny {
				t.Fatalf("deny=%v want %v: %s", reason != "", tc.deny, reason)
			}
		})
	}
}
