//go:build !windows

package backend

import (
	"os/exec"
	"syscall"
)

// A new session prevents an inherited controlling terminal, including /dev/tty.
func configureOnePasswordProcess(cmd *exec.Cmd) bool {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	return true
}
