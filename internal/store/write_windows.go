//go:build windows

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

// privateStoreRoot creates only missing components, with their final DACLs. An
// existing store parent must already be private; arbitrary parents are not fixed.
// Win32 lexical cleaning is intentional (unlike physical Unix link/.. traversal).
func privateStoreRoot(dir string, create bool) (*os.Root, error) {
	if secure.ValidateStorePath(dir) != nil {
		return nil, secure.ErrPrivateFile
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, secure.ErrPrivateFile
	}
	if filepath.Dir(absolute) == absolute {
		// A private UNC share root can contain stores directly. Volume roots
		// already exist: open and inspect, never create or repair their ACLs.
		root, err := os.OpenRoot(absolute)
		if err != nil {
			return nil, secure.ErrPrivateFile
		}
		dir, err := root.Open(".")
		if err == nil {
			defer dir.Close()
			if secure.CheckPrivate(dir) == nil {
				return root, nil
			}
		}
		root.Close()
		return nil, secure.ErrPrivateFile
	}
	parentPath, name := filepath.Dir(absolute), filepath.Base(absolute)
	parent, err := os.OpenRoot(parentPath)
	if os.IsNotExist(err) && create {
		parent, err = privateStoreRoot(parentPath, true)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil, os.ErrNotExist
		}
		return nil, secure.ErrPrivateFile
	}
	defer parent.Close()
	if create {
		if err := secure.CreatePrivateDirectory(parent, name); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	return secure.OpenPrivateDirectory(parent, name)
}

func openWriteRoot(dir string) (*os.Root, error) { return privateStoreRoot(dir, true) }

func ValidateDirectory(dir string) error {
	root, err := privateStoreRoot(dir, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("secret directory must be private and not a reparse point")
	}
	return root.Close()
}

func lockBusy(err error) bool {
	return os.IsExist(err) || errors.Is(err, secure.ErrPrivateBusy)
}

func withLock(dir string, wait time.Duration, work func() error) error {
	root, err := openWriteRoot(dir)
	if err != nil {
		return errors.New("cannot open private secret directory")
	}
	defer root.Close()
	const lock = ".write-lock"
	deadline := time.Now().Add(wait)
	for {
		err = secure.CreatePrivateDirectory(root, lock)
		if err == nil {
			break
		}
		if !lockBusy(err) {
			return errors.New("cannot acquire write lock")
		}
		if !time.Now().Before(deadline) {
			if !os.IsExist(err) {
				return errors.New("cannot acquire write lock")
			}
			return fmt.Errorf("write lock timed out after %d s; verify its owner then manually remove .write-lock (never auto-stolen)", int(wait/time.Second))
		}
		time.Sleep(100 * time.Millisecond)
	}
	locked, err := secure.OpenPrivateDirectory(root, lock)
	if err != nil {
		return errors.New("cannot acquire write lock")
	}
	defer locked.Close()
	token, err := newToken()
	if err != nil {
		_ = root.Remove(lock)
		return err
	}
	if err := writePrivateChild(locked, "token", []byte(token+"\n")); err != nil {
		_ = locked.Remove("token")
		_ = root.Remove(lock)
		return errors.New("cannot write lock token")
	}
	defer func() {
		// Both the token and directory identity must still belong to this owner.
		owner, err := readPrivateChild(locked, "token")
		defer secure.Clear(owner)
		if err != nil || string(owner) != token+"\n" || !sameDirectory(root, lock, locked) {
			return
		}
		_ = locked.Remove("token")
		_ = root.Remove(lock)
	}()
	if err := cleanStaleScratch(root); err != nil {
		return err
	}
	return work()
}

func sameDirectory(parent *os.Root, name string, expected *os.Root) bool {
	current, err := secure.OpenPrivateDirectory(parent, name)
	if err != nil {
		return false
	}
	defer current.Close()
	a, err := current.Stat(".")
	if err != nil {
		return false
	}
	b, err := expected.Stat(".")
	return err == nil && os.SameFile(a, b)
}

func writePrivateChild(root *os.Root, name string, data []byte) error {
	file, err := secure.CreatePrivateFile(root, name)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return secure.ErrPrivateFile
	}
	return nil
}

func cleanStaleScratch(root *os.Root) error {
	parent, err := root.Open(".")
	if err != nil {
		return errors.New("cannot inspect private write directory")
	}
	defer parent.Close()
	entries, err := parent.ReadDir(-1)
	if err != nil {
		return errors.New("cannot inspect private write directory")
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), ".secret-stash.") {
			continue
		}
		scratch, err := secure.OpenPrivateDirectory(root, entry.Name())
		if err != nil {
			continue
		}
		body, err := readPrivateChild(scratch, "owner")
		owned := err == nil && string(body) == "secret-stash-v1\n" && sameDirectory(root, entry.Name(), scratch)
		secure.Clear(body)
		scratch.Close()
		if owned && root.RemoveAll(entry.Name()) != nil {
			return errors.New("cannot clean private write directory")
		}
	}
	return nil
}

// A bounded native busy classification is deliberately narrower than permission
// denial. Access denied must never trigger the old Windows blanket retry.
func retryPrivateBusy(work func() error) error {
	deadline := time.Now().Add(300 * time.Millisecond)
	for {
		err := work()
		if !errors.Is(err, secure.ErrPrivateBusy) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_DELETE_PENDING) {
			return err
		}
		if !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func regularTarget(root *os.Root, name string) error {
	return retryPrivateBusy(func() error {
		file, err := secure.OpenPrivateFile(root, name)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return file.Close()
	})
}

func atomicReplace(root *os.Root, name string, data []byte) error {
	if err := regularTarget(root, name); err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	scratchName := ".secret-stash." + token
	if err := secure.CreatePrivateDirectory(root, scratchName); err != nil {
		return errors.New("cannot create private write directory")
	}
	defer root.RemoveAll(scratchName)
	scratch, err := secure.OpenPrivateDirectory(root, scratchName)
	if err != nil {
		return errors.New("cannot create private write directory")
	}
	defer scratch.Close()
	if err := writePrivateChild(scratch, "owner", []byte("secret-stash-v1\n")); err != nil {
		return errors.New("cannot create private write directory")
	}
	// FlushFileBuffers is mandatory on the writable replacement before publish.
	if err := writePrivateChild(scratch, "replacement", data); err != nil {
		return errors.New("atomic store update failed")
	}
	if err := regularTarget(root, name); err != nil {
		return err
	}
	// Go 1.26.10 Renameat uses NtSetInformationFile with an anchored destination,
	// replacement semantics and a non-copying fallback. No delete-first window.
	if err := retryPrivateBusy(func() error {
		return root.Rename(filepath.Join(scratchName, "replacement"), name)
	}); err != nil {
		return errors.New("atomic store update failed")
	}
	return nil
}
