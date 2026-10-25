//go:build !windows

package store

import (
	"os"
	"syscall"
)

func privateAgeInfo(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		return false
	}
	if directory {
		return info.IsDir() && info.Mode().Perm()&0700 == 0700
	}
	return info.Mode().IsRegular() && info.Mode().Perm()&0100 == 0
}
