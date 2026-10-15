package paths

import (
	"errors"
	"io/fs"
	"os"
	"runtime"
	"syscall"
)

// An invalid Windows filename is not a possible file-input source. Permission
// and I/O failures remain indeterminate, and other platforms keep their rules.
func missingOperand(err error) bool {
	return os.IsNotExist(err) || runtime.GOOS == "windows" && invalidWindowsOperand(err)
}

func invalidWindowsOperand(err error) bool {
	if errors.Is(err, fs.ErrInvalid) {
		return true
	}
	// Win32 ERROR_INVALID_NAME, ERROR_BAD_PATHNAME, ERROR_DIRECTORY.
	for _, code := range []syscall.Errno{123, 161, 267} {
		if errors.Is(err, code) {
			return true
		}
	}
	return false
}
