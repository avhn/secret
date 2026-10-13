//go:build windows

package cli

// Windows child supervision needs a Job Object and console-control handling;
// until the M5a gate, reject run and exec before starting a child. This is a
// value-free error and no secret enters argv, diagnostics, or child output.
func launchUnsupported() bool { return true }

func (c command) execChild(args, env []string) int {
	return c.fail("run and exec are unsupported on Windows before M5a", 1)
}
func (c command) runChild(args, env []string, values [][]byte) int {
	return c.fail("run and exec are unsupported on Windows before M5a", 1)
}
