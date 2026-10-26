//go:build windows

package policy

import "golang.org/x/sys/windows"

// Preserve refs/ link text: os.Symlink replaces it with refs\ on Windows.
func audit29HeadSymlink(target, name string) error {
	link, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	text, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	const allowUnprivilegedCreate = 0x2 // SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	return windows.CreateSymbolicLink(link, text, allowUnprivilegedCreate)
}
