package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// Exercise the final fuzz seed after other analyses have populated metadata and
// configured-path caches. All paths are native absolute synthetic paths, so the
// Windows case cannot pass merely by rejecting a volume-less cwd at entry.
func TestAnalyzeSequentialMetadata(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	const nested = `bash -c 'bash -c "cat .env"'`
	for _, name := range []string{"first", "second"} {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"one.cfg", "two.cfg", "README.md"} {
			if err := os.WriteFile(filepath.Join(dir, file), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, config := range []string{"one.cfg", "two.cfg", ""} {
		t.Setenv("KUBECONFIG", config)
		for _, name := range []string{"first", "second"} {
			dir := filepath.Join(root, name)
			for _, file := range []string{"one.cfg", "two.cfg", "README.md"} {
				if got := Analyze("cat "+file, dir, root, check); (got != "") != (file == config) {
					t.Fatalf("cwd=%s config=%q file=%s: reason=%q", name, config, file, got)
				}
			}
			if got := Analyze(nested, dir, root, check); got != roles.Reader {
				t.Fatalf("nested seed after cwd=%s config=%q: reason=%q", name, config, got)
			}
		}
	}
}
