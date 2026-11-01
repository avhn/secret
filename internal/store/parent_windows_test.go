//go:build windows

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsTrustedStoreParent(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit", true: "inherited"}[inherited], func(t *testing.T) {
			dir := testutil.TempDir(t)
			testutil.TrustStoreParent(t, dir, inherited)
			root, err := openWriteRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			parent, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if secure.CheckStoreDirectory(parent) != nil || secure.CheckPrivate(parent) == nil {
				t.Fatal("store/private policies not separated")
			}
			if file, err := secure.CreatePrivateFile(root, "forbidden"); err == nil {
				file.Close()
				t.Fatal("private create accepted trusted-only parent")
			}
			path := filepath.Join(dir, "synthetic.secret")
			for _, value := range [][]byte{[]byte("synthetic-first"), []byte("synthetic-replaced")} {
				if err := StashWithSecretsDir(dir, path, "TOKEN", nil, value); err != nil {
					t.Fatal(err)
				}
				got, err := ReadFile(path)
				if err != nil || !bytes.Equal(got, append(append([]byte("TOKEN="), value...), '\n')) {
					t.Fatal("store round trip failed")
				}
				secure.Clear(got)
				assertPrivateFixture(t, path)
			}
			if file, err := secure.OpenPrivateFile(root, "synthetic.secret"); err == nil {
				file.Close()
				t.Fatal("strict opener accepted store parent")
			}
			if err := syncManifestDirectory(root); err != nil {
				t.Fatal(err)
			}
			if err := secure.CreatePrivateDirectory(root, ".secret-stash.stale"); err != nil {
				t.Fatal(err)
			}
			scratch, err := secure.OpenPrivateDirectory(root, ".secret-stash.stale")
			if err != nil {
				t.Fatal(err)
			}
			if err := writePrivateChild(scratch, "owner", []byte("secret-stash-v1\n")); err != nil {
				t.Fatal(err)
			}
			scratch.Close()
			assertPrivateFixture(t, filepath.Join(dir, ".secret-stash.stale"))
			assertPrivateFixture(t, filepath.Join(dir, ".secret-stash.stale", "owner"))
			// An inherited lookalike is never eligible for stale cleanup.
			if err := os.Mkdir(filepath.Join(dir, ".secret-stash.unowned"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := withLock(dir, time.Second, func() error {
				assertPrivateFixture(t, filepath.Join(dir, ".write-lock"))
				assertPrivateFixture(t, filepath.Join(dir, ".write-lock", "token"))
				if _, err := root.Stat(".secret-stash.stale"); !os.IsNotExist(err) {
					t.Fatal("marked stale scratch retained")
				}
				if _, err := root.Stat(".secret-stash.unowned"); err != nil {
					t.Fatal("unowned scratch removed")
				}
				if err := withLock(dir, 0, func() error { t.Fatal("contending lock entered"); return nil }); err == nil {
					t.Fatal("contention accepted")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			before, err := ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer secure.Clear(before)
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(path, 0600)
			if err := StashWithSecretsDir(dir, path, "TOKEN", nil, []byte("must-not-publish")); err == nil {
				t.Fatal("read-only publication succeeded")
			}
			after, err := ReadFile(path)
			defer secure.Clear(after)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed publication changed bytes")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatal("failed publication leaked lock or scratch")
			}
			// Implicitly created store directories retain the strict creation policy.
			nested := filepath.Join(dir, "new", "nested")
			created, err := openWriteRoot(nested)
			if err != nil {
				t.Fatal(err)
			}
			created.Close()
			assertPrivateFixture(t, filepath.Dir(nested))
			assertPrivateFixture(t, nested)
		})
	}
}
