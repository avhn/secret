package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestProtected checks names, aliases and cwd/workdir anchoring using synthetic files.
func TestProtected(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(root, "work"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(root, "work", "alias.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/synthetic/.netrc", filepath.Join(root, "work", "dangling.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loop.txt", filepath.Join(root, "work", "loop.txt")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path, workdir string
		protected     bool
	}{
		{".env", "work", true}, {"alias.txt", "work", true}, {"dangling.txt", "work", true}, {"loop.txt", "work", true},
		{".env.example", "work", false}, {"config.json", "work", false}, {"/repo/.AWS/CREDENTIALS", "", true},
		{"/repo/.SSH/ID_ED25519.PUB", "", false}, {"/proc/123/task/456/environ", "", true},
		{"~/notes.secret", "", true}, {"src/app.go", "work", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if got := Protected(tc.path, root, tc.workdir, home); got != tc.protected {
				t.Fatalf("protected=%v, want %v", got, tc.protected)
			}
		})
	}
}

// TestTreeProtectedFailures injects incomplete walks, loops and exhausted budgets.
func TestTreeProtectedFailures(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	entry, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "safe.go"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	entry, err = os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		walk  func(string, fs.WalkDirFunc) error
		clock func() time.Time
	}{
		{"walk error", func(string, fs.WalkDirFunc) error { return errors.New("synthetic I/O") }, time.Now},
		{"permission", func(p string, visit fs.WalkDirFunc) error { return visit(p, nil, fs.ErrPermission) }, time.Now},
		{"symlink loop", func(p string, visit fs.WalkDirFunc) error { return visit(p, nil, fs.ErrInvalid) }, time.Now},
		{"budget", func(p string, visit fs.WalkDirFunc) error {
			for i := 0; i < 4097; i++ {
				if err := visit(filepath.Join(p, "safe.go"), entry[0], nil); err != nil {
					return err
				}
			}
			return nil
		}, time.Now},
		{"deadline", func(p string, visit fs.WalkDirFunc) error { return visit(filepath.Join(p, "safe.go"), entry[0], nil) }, func() time.Time { now = now.Add(time.Second); return now }},
		{"ignored callback failure", func(p string, visit fs.WalkDirFunc) error { _ = visit(p, nil, fs.ErrPermission); return nil }, time.Now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !treeProtected(root, root, root, tc.walk, tc.clock) {
				t.Fatal("incomplete tree allowed")
			}
		})
	}
}

// TestTreeProtected rejects protected descendants and incomplete symlink scopes.
func TestTreeProtected(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe.go"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if TreeProtected(root, root, root) {
		t.Fatal("safe metadata tree rejected")
	}
	if err := os.Symlink(root, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if !TreeProtected(root, root, root) {
		t.Fatal("unscanned link accepted")
	}
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if !TreeProtected(root, root, root) {
		t.Fatal("protected descendant accepted")
	}
}
