//go:build windows

package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestWindowsIdentityPublicPolicyControls(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"in", "README.md", "src/util.ts"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	syntheticRepo(t, root, 2, "in", "README.md", "src/util.ts")
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_COMMON_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("KUBECONFIG", filepath.Join(root, "custom.cfg"))
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`sed '/x/d' in`, false},
		{`sed -n '/process.env/p' src/util.ts`, false},
		{`command run0 /bin/true`, false},
		{`docker run -v "$PWD":/src node:20 npm test`, false},
		{`printf '%s' 'print(open("README.md").read())' | python3`, false},
		{`printf '%s' 'print(open("custom.cfg").read())' | python3`, true},
		{`printf '%s' 'open my $f, "<", "README.md"; print <$f>' | perl`, false},
		{`echo synthetic > .git/config`, true},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if reason := Analyze(tc.source, root, root, check); (reason != "") != tc.deny {
				t.Errorf("reason=%q want deny=%v", reason, tc.deny)
			}
		})
	}
}
