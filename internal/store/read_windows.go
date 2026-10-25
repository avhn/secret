//go:build windows

package store

import (
	"io"
	"os"
	"path/filepath"

	"github.com/avhn/secret/internal/secure"
)

func openNoFollow(root *os.Root, name string) (*os.File, error) {
	return secure.OpenPrivateFile(root, name)
}

// ReadFile anchors the private parent and checks the final handle before reading
// any bytes. Neither a final reparse point nor a mode-only fixture is private.
func ReadFile(path string) ([]byte, error) {
	if secure.ValidateStorePath(path) != nil {
		return nil, secure.ErrPrivateFile
	}
	root, err := privateStoreRoot(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRegular(root, filepath.Base(path))
}

// ACL checks happen on openNoFollow's handle, never on emulated Unix mode bits.
func privateMode(os.FileInfo) bool { return true }

func readPrivateChild(root *os.Root, name string) ([]byte, error) {
	file, err := secure.OpenPrivateFile(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

func openReadRoot(dir string) (*os.Root, error) { return privateStoreRoot(dir, false) }

// Windows offers no supported directory FlushFileBuffers contract here. Require
// a live private anchor but do not turn a successful data-flushed publication
// into permanent recovery by trying to Sync a read-only directory handle.
// This is not a power-loss durability guarantee.
func syncManifestDirectory(root *os.Root) error {
	if root == nil {
		return secure.ErrRecovery
	}
	dir, err := root.Open(".")
	if err != nil {
		return secure.ErrRecovery
	}
	defer dir.Close()
	if secure.CheckPrivate(dir) != nil {
		return secure.ErrRecovery
	}
	return nil
}
