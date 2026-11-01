//go:build windows

// Package testutil creates synthetic private fixtures, never real stores.
package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
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
		// Deliberately insecure fixture. Mode bits mean nothing on Windows and a
		// file inside a private directory inherits a user-only DACL, which store
		// files may legitimately carry. Grant Everyone explicitly instead.
		if err := os.WriteFile(path, data, mode); err != nil {
			return err
		}
		return broadenDACL(path)
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

// broadenDACL replaces a disposable synthetic file's DACL with a protected
// Everyone full-access entry. Use it only on fixtures, never on a user's store.
func broadenDACL(path string) error {
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		return err
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
