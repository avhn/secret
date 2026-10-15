package paths

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestInvalidWindowsOperand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		missing bool
	}{
		{"invalid name", syscall.Errno(123), true},
		{"bad pathname", syscall.Errno(161), true},
		{"not directory", syscall.Errno(267), true},
		{"invalid filesystem name", fs.ErrInvalid, true},
		{"permission", fs.ErrPermission, false},
		{"access denied", syscall.Errno(5), false},
		{"I/O", syscall.Errno(1117), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := &os.PathError{Op: "lstat", Path: "synthetic", Err: fmt.Errorf("wrapped: %w", tc.err)}
			if got := invalidWindowsOperand(err); got != tc.missing {
				t.Errorf("invalid=%v want=%v", got, tc.missing)
			}
			if got := missingOperand(err); got != (runtime.GOOS == "windows" && tc.missing) {
				t.Errorf("platform missing=%v", got)
			}
		})
	}
}

func TestWindowsDataOperands(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows invalid-name behavior")
	}
	root := t.TempDir()
	for _, name := range []string{">", `{"a": 1}`} {
		if Protected(name, root, "", root) {
			t.Errorf("inert data operand %q treated as a file", name)
		}
	}
}

func TestDirenvProtected(t *testing.T) {
	root := t.TempDir()
	if !Protected(".envrc", root, "", root) {
		t.Fatal("direnv input was not protected")
	}
}
