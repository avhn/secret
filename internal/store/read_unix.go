//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package store

import (
	"os"
	"syscall"
)

func openNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}
