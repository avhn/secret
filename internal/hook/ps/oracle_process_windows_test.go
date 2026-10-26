//go:build windows

package ps

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows"
)

// Candidate text is never executed. The fixed oracle cannot create candidate
// jobs, but cancellation still kills its full process tree. Resolve taskkill
// from the OS directory, never from PATH or an inherited user directory.
func configureOracleProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		directory, err := windows.GetSystemDirectory()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			killer := exec.CommandContext(ctx, filepath.Join(directory, "taskkill.exe"), "/PID", strconv.Itoa(cmd.Process.Pid), "/T", "/F")
			killer.WaitDelay = time.Second
			if killer.Run() == nil {
				return nil
			}
		}
		// Always reap the direct child even if the OS tree utility failed. A timeout
		// is a test failure irrespective of the fallback's result.
		return cmd.Process.Kill()
	}
}
