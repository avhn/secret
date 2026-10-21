//go:build linux || darwin

package cli

import "golang.org/x/sys/unix"

// silenceEcho clears ECHO before the caller displays a hidden-input prompt, so
// bytes typed ahead of term.ReadPassword are never echoed. The returned function
// restores the exact prior terminal settings.
func silenceEcho(fd int) (func() error, error) {
	before, err := unix.IoctlGetTermios(fd, getTermios)
	if err != nil {
		return nil, err
	}
	quiet := *before
	quiet.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(fd, setTermios, &quiet); err != nil {
		return nil, err
	}
	return func() error { return unix.IoctlSetTermios(fd, setTermios, before) }, nil
}
