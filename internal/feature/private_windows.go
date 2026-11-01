//go:build windows

package feature

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/secure"
)

// Start at an explicit native volume, then retain and verify every ancestor.
// Do not treat a volume-less rooted path, device namespace or stream as a home.
func featurePathRoot(path string) (*os.Root, []string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || secure.ValidateStorePath(path) != nil {
		return nil, nil, secure.ErrPrivateFile
	}
	volume := filepath.VolumeName(path) + string(filepath.Separator)
	if path == volume {
		return nil, nil, secure.ErrPrivateFile
	}
	parts := strings.Split(strings.TrimPrefix(path, volume), string(filepath.Separator))
	if len(parts) > 256 {
		return nil, nil, secure.ErrPrivateFile
	}
	root, err := os.OpenRoot(volume)
	return root, parts, err
}

func createFeatureDirectory(root *os.Root, name string) error {
	return secure.CreatePrivateDirectory(root, name)
}
func openFeatureDirectory(root *os.Root, name string, private bool) (*os.Root, error) {
	if private {
		return secure.OpenPrivateDirectory(root, name)
	}
	return root.OpenRoot(name)
}
func validateFeatureDirectory(root *os.Root, private bool) error {
	if !private {
		return nil
	}
	file, err := root.Open(".")
	if err != nil {
		return secure.ErrPrivateFile
	}
	defer file.Close()
	return secure.CheckPrivate(file)
}

// Modes are not an ACL certificate. Every private open/create verifies handles.
func featureDirectoryMode(os.FileInfo, bool) bool { return true }
func featureFileMode(os.FileInfo) bool            { return true }
func operatorManifestMode(os.FileInfo) bool       { return true }
func createFeatureFile(root *os.Root, name string) (*os.File, error) {
	return secure.CreatePrivateFile(root, name)
}
func protectFeatureFile(file *os.File) error { return secure.CheckPrivate(file) }
func openFeatureFile(root *os.Root, name string) (*os.File, error) {
	return secure.OpenPrivateFile(root, name)
}
func openOperatorFile(root *os.Root, name string) (*os.File, error) {
	return secure.OpenStoreFile(root, name)
}

// File Sync and anchored Rename errors remain mandatory. Windows does not offer
// a supported directory FlushFileBuffers contract here: verify the live private
// anchor instead, without claiming power-loss directory durability.
func syncFeatureDirectory(root *os.Root) error { return validateFeatureDirectory(root, true) }

func validateFeaturePayload(root *os.Root, expected os.FileInfo) error {
	file, err := secure.OpenPrivateFile(root, "payload")
	if err != nil {
		return secure.ErrPrivateFile
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(expected, info) {
		return secure.ErrPrivateFile
	}
	return nil
}

func doctorPrivateStatus(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return "unavailable"
	}
	defer file.Close()
	if secure.CheckPrivate(file) != nil {
		if secure.CheckStoreDirectory(file) == nil {
			return "trusted_parent"
		}
		return "insecure"
	}
	return "private"
}

// Do not resolve away a final parent reparse point before checking its handle.
func openOperatorDirectory(path string) (*os.Root, error) {
	return openOperatorDirectoryWithRoot(path, os.OpenRoot)
}

func openOperatorDirectoryWithRoot(path string, openRoot func(string) (*os.Root, error)) (*os.Root, error) {
	if secure.ValidateStorePath(path) != nil {
		return nil, secure.ErrPrivateFile
	}
	parent, err := openRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if filepath.Dir(path) == path {
		file, err := parent.Open(".")
		if err == nil {
			defer file.Close()
			if secure.CheckStoreDirectory(file) == nil {
				return parent, nil
			}
		}
		parent.Close()
		return nil, secure.ErrPrivateFile
	}
	defer parent.Close()
	return secure.OpenStoreDirectory(parent, filepath.Base(path))
}
