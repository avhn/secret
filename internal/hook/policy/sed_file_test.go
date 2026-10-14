package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestSedScriptFileUncertain rejects script sources that cannot be read as bounded regular files.
func TestSedScriptFileUncertain(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, ".env")
	if err := os.WriteFile(marker, []byte("SYNTHETIC MARKER\n"), 0600); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(root, "safe.sed")
	if err := os.WriteFile(safe, []byte("p\n"), 0600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(root, "large.sed")
	if err := os.WriteFile(large, []byte(strings.Repeat("#x\n", 3000)), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.sed")
	linkErr := os.Symlink(safe, link)
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, source := range []string{"-", "/dev/stdin", "/proc/self/fd/0", filepath.Join(root, "missing.sed"), root, large} {
		t.Run(source, func(t *testing.T) {
			if got := AnalyzeArgv([]string{"sed", "-f", source, "in.txt"}, root, root, check); got == "" {
				t.Fatal("uncertain sed script source allowed")
			}
		})
	}
	if linkErr == nil {
		if got := AnalyzeArgv([]string{"sed", "-f", link, "in.txt"}, root, root, check); got == "" {
			t.Fatal("symlinked script source allowed")
		}
	}
	if got := AnalyzeArgv([]string{"sed", "-f", safe, "in.txt"}, root, root, check); got != "" {
		t.Fatalf("safe regular script denied: %s", got)
	}
}
