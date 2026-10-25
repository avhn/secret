package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMetadataRetainsResolutionResults(t *testing.T) {
	for _, failure := range []error{nil, os.ErrPermission, os.ErrNotExist} {
		cache := make(map[string]pathResult)
		calls := 0
		resolve := func(name string) (string, error) { calls++; return name, failure }
		for i := 0; i < 3; i++ {
			name, err := rememberPath(&cache, "synthetic", resolve)
			if name != "synthetic" || !errors.Is(err, failure) {
				t.Fatalf("name=%q err=%v", name, err)
			}
		}
		if calls != 1 {
			t.Errorf("resolver calls=%d, want 1", calls)
		}
	}
	cache := make(map[string]pathResult)
	for i := 0; i < maxMetadataEntries+1; i++ {
		name := strings.Repeat("x", i)
		rememberPath(&cache, name, func(name string) (string, error) { return name, nil })
	}
	if len(cache) != maxMetadataEntries {
		t.Errorf("cache length=%d", len(cache))
	}
}

func TestMetadataMatchesUncachedClassification(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("KUBECONFIG", "configured.cfg")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	var metadata Metadata
	for _, name := range []string{"README.md", ".env", ".yarnrc.yml", "configured.cfg", "./configured.cfg", "missing/../public.txt", ".aws/config", strings.Repeat("a", 300)} {
		for i := 0; i < 3; i++ {
			if got, want := metadata.Protected(name, root, "", root), Protected(name, root, "", root); got != want {
				t.Errorf("Protected(%q)=%v, want %v", name, got, want)
			}
			if got, want := metadata.LexicalProtected(name, root, root), LexicalProtected(name, root, root); got != want {
				t.Errorf("LexicalProtected(%q)=%v, want %v", name, got, want)
			}
			if got, want := metadata.ConfiguredProtected(name, root, "", root, "configured.cfg"), ConfiguredProtected(name, root, "", root, "configured.cfg"); got != want {
				t.Errorf("ConfiguredProtected(%q)=%v, want %v", name, got, want)
			}
		}
	}
}

func TestMetadataPreservesRawPathsAndAnalysisScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix physical link/.. contract; Windows counterpart covers native traversal and metadata scope")
	}
	root := t.TempDir()
	t.Setenv("HOME", root)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	for _, dir := range []string{".aws/child", "public"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, ".aws", "child"), link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	var metadata Metadata
	if !metadata.Protected("link/../credentials", root, "", root) {
		t.Fatal("raw link/.. lost its physical credential witness")
	}
	if metadata.Protected("public/../credentials", root, "", root) {
		t.Fatal("ordinary public path became protected")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "public"), link); err != nil {
		t.Fatal(err)
	}
	var next Metadata
	if next.Protected("link/../credentials", root, "", root) {
		t.Fatal("metadata survived into a fresh analysis")
	}
}
