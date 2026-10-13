//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package store

import "os"

// Root prevents escape; on platforms without O_NOFOLLOW the final component
// is checked before opening and the opened handle is checked for regularity.
func openNoFollow(root *os.Root, name string) (*os.File, error) {
	return root.Open(name)
}
