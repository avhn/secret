//go:build !windows

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ValidateDirectory rejects a symlinked or non-directory secrets location.
// Like Bash, it checks only the final component, not every ancestor.
func ValidateDirectory(dir string) error {
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret directory must not be a symlink")
	}
	return nil
}

func withLock(dir string, wait time.Duration, work func() error) error {
	if err := ValidateDirectory(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("cannot create secret directory")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret directory must not be a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open secret directory")
	}
	defer root.Close()
	if err := root.Chmod(".", 0700); err != nil {
		return errors.New("cannot protect secret directory")
	}
	return withRootLock(root, wait, func(*os.Root) error { return work() })
}

// withRootLock keeps the lock, callback and publication on one directory handle.
func withRootLock(root *os.Root, wait time.Duration, work func(*os.Root) error) error {
	const lock = ".write-lock"
	var err error
	deadline := time.Now().Add(wait)
	for {
		err = root.Mkdir(lock, 0700)
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
	token, err := newToken()
	if err != nil {
		_ = root.Remove(lock)
		return err
	}
	if err = root.WriteFile(filepath.Join(lock, "token"), []byte(token+"\n"), 0600); err != nil {
		_ = root.Remove(filepath.Join(lock, "token"))
		_ = root.Remove(lock)
		return errors.New("cannot write lock token")
	}
	defer func() {
		owner, e := root.ReadFile(filepath.Join(lock, "token"))
		if e == nil && string(owner) == token+"\n" {
			_ = root.Remove(filepath.Join(lock, "token"))
			_ = root.Remove(lock)
		}
	}()
	if err := cleanStaleScratch(root); err != nil {
		return err
	}
	return work(root)
}

// lockBusy reports contention without retrying permanent permission errors.
func lockBusy(err error) bool {
	return os.IsExist(err)
}

// A fresh owner may remove only our marked scratch directories after the
// operator verifies and clears a killed writer's tokened lock.
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
		path := entry.Name()
		marker, err := root.Lstat(filepath.Join(path, "owner"))
		if err != nil || !marker.Mode().IsRegular() {
			continue
		}
		body, err := root.ReadFile(filepath.Join(path, "owner"))
		if err != nil || string(body) != "secret-stash-v1\n" {
			continue
		}
		if err := root.RemoveAll(path); err != nil {
			return errors.New("cannot clean private write directory")
		}
	}
	return nil
}

func regularTarget(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing symlink or non-regular write target")
	}
	return nil
}

// atomicReplace creates a private sibling and publishes only after syncing data.
func atomicReplace(root *os.Root, name string, data []byte) error {
	return atomicReplaceChecked(root, name, data, false, nil)
}

func atomicReplaceChecked(root *os.Root, name string, data []byte, strict bool, checkpoint func(string) error) error {
	check := func(phase string) error {
		if checkpoint != nil {
			return checkpoint(phase)
		}
		return nil
	}
	if err := regularTarget(root, name); err != nil {
		return err
	}
	token, err := newToken()
	if err != nil {
		return err
	}
	scratch := ".secret-stash." + token
	if err := root.Mkdir(scratch, 0700); err != nil {
		return errors.New("cannot create private write directory")
	}
	defer root.RemoveAll(scratch)
	// A crash before the marker exists leaves only an empty unmarked directory.
	if err := root.WriteFile(filepath.Join(scratch, "owner"), []byte("secret-stash-v1\n"), 0600); err != nil {
		return errors.New("cannot create private write directory")
	}
	file, err := root.OpenFile(filepath.Join(scratch, "replacement"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("atomic store update failed")
	}
	if err = check("scratch-write"); err == nil {
		_, err = file.Write(data)
	}
	if err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = check("file-sync"); err == nil {
		err = file.Sync()
	}
	if err != nil {
		_ = file.Close()
		return errors.New("atomic store update failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("atomic store update failed")
	}
	if err = regularTarget(root, name); err != nil {
		return err
	}
	if err = check("rename"); err == nil {
		err = root.Rename(filepath.Join(scratch, "replacement"), name)
	}
	if err != nil {
		return errors.New("atomic store update failed")
	}
	// Age requires directory durability. A post-publication failure is not rollback.
	if strict {
		if check("directory-sync") != nil {
			return ErrAgeDurability
		}
		parent, e := root.Open(".")
		if e != nil {
			return ErrAgeDurability
		}
		defer parent.Close()
		if parent.Sync() != nil {
			return ErrAgeDurability
		}
		return nil
	}
	// Publishing succeeded; directory sync only hardens legacy crash durability.
	if runtime.GOOS != "windows" {
		if parentFile, e := root.Open("."); e == nil {
			_ = parentFile.Sync()
			_ = parentFile.Close()
		}
	}
	return nil
}
