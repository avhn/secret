//go:build !windows

package backend

import (
	"os/exec"
	"syscall"
)

// configureProviderProcess kills provider descendants when the deadline expires.
func configureProviderProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// stopProviderProcess cleans up descendants after an inherited pipe expires.
func stopProviderProcess(cmd *exec.Cmd) { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
