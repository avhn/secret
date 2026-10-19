//go:build windows

package feature

import "os/exec"

// configureImporterProcess retains CommandContext's direct-child cancellation on Windows.
// Operator validation rejects Windows before running an importer until M5a.
func configureImporterProcess(command *exec.Cmd) {}

// stopImporterProcess has no process-group support on Windows.
func stopImporterProcess(command *exec.Cmd) {}
