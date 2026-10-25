//go:build !windows

package paths

import (
	"io/fs"
	"os"
)

// Home preserves the Unix hook's explicit HOME lookup.
func Home() string { return os.Getenv("HOME") }

// ValidHome retains Unix behavior when HOME is empty or relative.
func ValidHome(_ string) bool { return true }

// ValidPath adds no native Windows restrictions to Unix path spelling.
func ValidPath(_ string) bool { return true }

func nativeName(name string) string { return name }

func physicalLink(info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }

func sameNativePath(_, _ string) bool { return false }

func nativeProtected(_, _ string) bool { return false }

func nativeConfigProtected(_, _, _, _, _ string) bool { return false }

func nativeGitProtected(_, _, _, _ string) bool { return false }

// The shared metadata walker calls this only on Windows.
func nativePhysical(_ string) (string, error) { return "", fs.ErrInvalid }
