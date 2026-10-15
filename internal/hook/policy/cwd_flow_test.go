package policy

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/roles"
)

func TestAudit15CWDSetBudget(t *testing.T) {
	root := t.TempDir()
	a := &analyzer{}
	var dirs []string
	for i := 0; i < maxWorkingDirectories; i++ {
		dirs = append(dirs, filepath.Join(root, fmt.Sprintf("dir-%d", i)))
	}
	if got := a.cwdUnion(dirs, dirs); len(got) != maxWorkingDirectories || a.reason != "" {
		t.Fatalf("dedup result=%d reason=%q", len(got), a.reason)
	}
	if got := a.cwdUnion(dirs, []string{filepath.Join(root, "extra")}); got != nil || a.reason != roles.Indeterminate {
		t.Fatalf("cwd budget not enforced: %q", a.reason)
	}
}
