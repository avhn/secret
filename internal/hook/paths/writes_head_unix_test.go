//go:build !windows

package paths

import "os"

var gitHeadSymlink = os.Symlink
