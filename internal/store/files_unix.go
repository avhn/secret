//go:build !windows

package store

import (
	"errors"
	"os"

	"github.com/avhn/secret/internal/secure"
)

// ReadFile preserves the legacy Unix reader, including its symlink behavior.
func ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

func openWriteRoot(dir string) (*os.Root, error) {
	if err := ValidateDirectory(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create secret directory")
	}
	if err := ValidateDirectory(dir); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errors.New("cannot open store directory")
	}
	return root, nil
}

func privateMode(info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }

func openReadRoot(dir string) (*os.Root, error) { return os.OpenRoot(dir) }

func syncManifestDirectory(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return secure.ErrRecovery
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return secure.ErrRecovery
	}
	return nil
}
