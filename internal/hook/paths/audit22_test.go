package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit22SingularConfiguredPaths(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	// A native list separator is filename data for singular AWS paths.
	target := "first" + string(os.PathListSeparator) + "second"
	var metadata Metadata
	for _, candidate := range []string{target, "./" + target, "first", "second", "public.txt"} {
		want := candidate == target || candidate == "./"+target
		if got := ConfiguredProtected(candidate, root, "", root, "", target); got != want {
			t.Errorf("ConfiguredProtected(%q)=%v want %v", candidate, got, want)
		}
		if got := metadata.ConfiguredProtected(candidate, root, "", root, "", target); got != want {
			t.Errorf("cached ConfiguredProtected(%q)=%v want %v", candidate, got, want)
		}
	}
	if !ConfiguredTreeProtected(root, root, root, "", target) {
		t.Error("tree lost literal configured target")
	}
	if ConfiguredTreeProtected(filepath.Join(root, "first"), root, root, "", target) {
		t.Error("singular target was split into independent names")
	}
}
