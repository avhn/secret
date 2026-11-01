//go:build windows

package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsTrustedStoreParentJunction(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.secret")
	if err := testutil.WriteFile(path, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	testutil.TrustStoreParent(t, dir, false)
	alias := filepath.Join(filepath.Dir(dir), "junction")
	makeWindowsJunction(t, alias, dir)
	if _, err := ReadFile(filepath.Join(alias, filepath.Base(path))); err == nil {
		t.Fatal("read accepted final junction parent")
	}
	if root, err := openWriteRoot(alias); err == nil {
		root.Close()
		t.Fatal("writer accepted final junction parent")
	}
}

func TestWindowsStoreVolumeRootPolicy(t *testing.T) {
	for _, path := range []string{`C:\`, `\\synthetic\share\`} {
		t.Run(path, func(t *testing.T) {
			dir := testutil.TempDir(t)
			testutil.TrustStoreParent(t, dir, true)
			calls := 0
			opener := func(name string) (*os.Root, error) {
				calls++
				if name != path {
					t.Fatalf("unexpected root %q", name)
				}
				return os.OpenRoot(dir)
			}
			for _, create := range []bool{false, true} {
				root, err := privateStoreRootWithOpener(path, create, opener)
				if err != nil {
					t.Fatal(err)
				}
				root.Close()
			}
			testutil.AddStoreParentUsersRead(t, dir)
			for _, create := range []bool{false, true} {
				if root, err := privateStoreRootWithOpener(path, create, opener); err == nil {
					root.Close()
					t.Fatal("root branch accepted Users read ACE")
				}
			}
			if calls != 4 {
				t.Fatal("root branch did not use injected directory")
			}
		})
	}
}
