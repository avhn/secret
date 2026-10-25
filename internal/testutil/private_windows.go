//go:build windows

// Package testutil creates synthetic private fixtures, never real stores.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/secure"
)

func TempDir(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func Mkdir(path string, mode os.FileMode) error {
	if mode != 0700 {
		return os.Mkdir(path, mode)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return secure.CreatePrivateDirectory(root, filepath.Base(path))
}

// MkdirAll creates private fixture ancestors without repairing existing ACLs.
func MkdirAll(path string, mode os.FileMode) error {
	if mode != 0700 {
		return os.MkdirAll(path, mode)
	}
	err := Mkdir(path, mode)
	if os.IsNotExist(err) {
		parent := filepath.Dir(path)
		if parent == path {
			return err
		}
		if err := MkdirAll(parent, mode); err != nil {
			return err
		}
		err = Mkdir(path, mode)
	}
	if !os.IsExist(err) {
		return err
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return secure.ErrPrivateFile
	}
	return secure.CheckPrivate(file)
}

func WriteFile(path string, data []byte, mode os.FileMode) error {
	if mode != 0600 {
		// Deliberately insecure fixture. It must not pass the protected-DACL check.
		return os.WriteFile(path, data, mode)
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	file, err := secure.CreatePrivateFile(root, filepath.Base(path))
	if os.IsExist(err) {
		file, err = root.OpenFile(filepath.Base(path), os.O_RDWR, 0)
		if err == nil && secure.CheckPrivate(file) != nil {
			file.Close()
			return secure.ErrPrivateFile
		}
		if err == nil {
			err = file.Truncate(0)
			if err != nil {
				file.Close()
			}
		}
	}
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
