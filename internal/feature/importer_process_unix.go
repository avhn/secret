//go:build !windows

package feature

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/secure"
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

func runImporter(ctx context.Context, name string, args []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	configureImporterProcess(command)
	command.WaitDelay = 250 * time.Millisecond
	stdout := &importerOutput{data: make([]byte, MaxImporterOutputBytes), cancel: cancel}
	stderr := &importerOutput{discard: true, cancel: cancel}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if errors.Is(err, exec.ErrWaitDelay) {
		stopImporterProcess(command)
	}
	if err != nil || stdout.failed || stderr.failed || ctx.Err() != nil {
		secure.Clear(stdout.data)
		return nil, secure.ErrTransaction
	}
	return stdout.data[:stdout.count], nil
}
