//go:build windows

package backend

import "os/exec"

// configureProviderProcess retains CommandContext's direct-child cancellation on Windows.
func configureProviderProcess(cmd *exec.Cmd) {}

// stopProviderProcess has no process-group support on Windows.
func stopProviderProcess(cmd *exec.Cmd) {}
