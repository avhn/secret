//go:build !windows

package feature

import (
	"os/exec"
	"syscall"
)

// configureImporterProcess kills importer descendants on cancellation or timeout.
func configureImporterProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
}

// stopImporterProcess cleans up descendants after an inherited pipe expires.
func stopImporterProcess(command *exec.Cmd) {
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
}
