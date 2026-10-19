//go:build !darwin

package cli

import "golang.org/x/term"

func operatorTerminalState(fd int) (*term.State, error) {
	return term.GetState(fd)
}
