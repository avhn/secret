//go:build !windows

package feature

import (
	"os"
	"path/filepath"
	"strings"
)

func featurePathRoot(path string) (*os.Root, []string, error) {
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) > 256 {
		return nil, nil, os.ErrInvalid
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	return root, parts, err
}

func createFeatureDirectory(root *os.Root, name string) error { return root.Mkdir(name, 0700) }
func openFeatureDirectory(root *os.Root, name string, _ bool) (*os.Root, error) {
	return root.OpenRoot(name)
}
func validateFeatureDirectory(*os.Root, bool) error { return nil }
func featureDirectoryMode(info os.FileInfo, private bool) bool {
	return !private || info.Mode().Perm() == 0700
}
func featureFileMode(info os.FileInfo) bool      { return info.Mode().Perm() == 0600 }
func operatorManifestMode(info os.FileInfo) bool { return info.Mode().Perm()&0077 == 0 }
func createFeatureFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
func protectFeatureFile(file *os.File) error                        { return file.Chmod(0600) }
func openFeatureFile(root *os.Root, name string) (*os.File, error)  { return root.Open(name) }
func openOperatorFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
func syncFeatureDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func validateFeaturePayload(*os.Root, os.FileInfo) error { return nil }

func doctorPrivateStatus(string) string { return "unsupported" }

func openOperatorDirectory(path string) (*os.Root, error) {
	// Normal platform aliases such as macOS /var and /tmp are valid explicit
	// input paths. Bind their resolved parent once; never follow a final alias.
	parent, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	return os.OpenRoot(parent)
}
