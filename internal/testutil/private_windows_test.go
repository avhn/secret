//go:build windows

package testutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
)

func TestMkdirAllRejectsInheritedDACL(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "inherited")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := testutil.MkdirAll(path, 0700); err != secure.ErrPrivateFile {
		t.Fatalf("inherited DACL accepted: %v", err)
	}
	if err := testutil.WriteFile(filepath.Join(path, "value"), []byte("synthetic"), 0600); err != secure.ErrPrivateFile {
		t.Fatalf("inherited parent DACL accepted for writing: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if secure.CheckPrivate(file) != secure.ErrPrivateFile {
		t.Fatal("fixture helper repaired an inherited DACL")
	}
}
