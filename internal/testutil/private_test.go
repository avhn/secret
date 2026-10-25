package testutil_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
)

func TestMkdirAllPrivateFixtures(t *testing.T) {
	root := testutil.TempDir(t)
	path := filepath.Join(root, "stub", "keychain", "secret", "demo")
	for range 2 {
		if err := testutil.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for dir := path; dir != root; dir = filepath.Dir(dir) {
		file, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		err = secure.CheckPrivate(file)
		file.Close()
		if err != nil {
			t.Fatal("fixture ancestor is not private")
		}
	}
	file := filepath.Join(path, "account")
	for _, value := range [][]byte{[]byte("synthetic-initial"), []byte("synthetic-replacement")} {
		if err := testutil.WriteFile(file, value, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, value) {
			t.Fatal("fixture readback failed")
		}
	}
	for _, name := range []string{file, filepath.Join(file, "child")} {
		if err := testutil.MkdirAll(name, 0700); err == nil {
			t.Error("regular file accepted as a fixture directory")
		}
	}
}
