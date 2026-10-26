//go:build !windows

package policy

import "os"

var audit29HeadSymlink = os.Symlink
