//go:build !windows

package secure

import "os"

// CheckPrivate checks the opened object rather than a second path lookup.
func CheckPrivate(file *os.File) error {
	if file == nil {
		return ErrPrivateFile
	}
	info, err := file.Stat()
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) || info.Mode().Perm()&0077 != 0 {
		return ErrPrivateFile
	}
	return nil
}

// CreatePrivateDirectory creates one private child without repairing its parent.
func CreatePrivateDirectory(root *os.Root, name string) error {
	if root == nil || !privateChildName(name) {
		return ErrPrivateFile
	}
	if err := root.Mkdir(name, 0700); err != nil {
		return privateError(err)
	}
	file, err := root.Open(name)
	if err != nil {
		return ErrPrivateFile
	}
	defer file.Close()
	return CheckPrivate(file)
}

// CreatePrivateFile verifies the parent before exclusive creation, and the new
// handle before returning it to a caller that can write secret bytes.
func CreatePrivateFile(root *os.Root, name string) (*os.File, error) {
	if root == nil || !privateChildName(name) {
		return nil, ErrPrivateFile
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, ErrPrivateFile
	}
	defer parent.Close()
	if CheckPrivate(parent) != nil {
		return nil, ErrPrivateFile
	}
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, privateError(err)
	}
	if CheckPrivate(file) != nil {
		file.Close()
		return nil, ErrPrivateFile
	}
	return file, nil
}

// OpenPrivateFile verifies final-component identity before any bytes are read.
func OpenPrivateFile(root *os.Root, name string) (*os.File, error) {
	if root == nil || !privateChildName(name) {
		return nil, ErrPrivateFile
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, ErrPrivateFile
	}
	defer parent.Close()
	if CheckPrivate(parent) != nil {
		return nil, ErrPrivateFile
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, privateError(err)
	}
	if !before.Mode().IsRegular() {
		return nil, ErrPrivateFile
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, privateError(err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || CheckPrivate(file) != nil {
		file.Close()
		return nil, ErrPrivateFile
	}
	return file, nil
}

func privateError(err error) error {
	if os.IsExist(err) {
		return os.ErrExist
	}
	if os.IsNotExist(err) {
		return os.ErrNotExist
	}
	return ErrPrivateFile
}
