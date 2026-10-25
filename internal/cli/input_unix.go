//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"github.com/avhn/secret/internal/secure"
	"golang.org/x/term"
	"io"
	"os"
)

func requireStashInput(*os.File) error { return nil }

func (c command) input(key string) ([]byte, error) {
	if fd := int(c.in.Fd()); term.IsTerminal(fd) {
		// Echo goes off before the prompt appears, so typed-ahead bytes stay hidden.
		restore, e := silenceEcho(fd)
		if e != nil {
			return nil, errors.New("no input")
		}
		fmt.Fprintf(c.errOut, "%s: ", key)
		value, e := term.ReadPassword(fd)
		fmt.Fprintln(c.errOut)
		if r := restore(); e != nil || r != nil {
			secure.Clear(value)
			return nil, errors.New("no input")
		}
		return value, nil
	}
	return io.ReadAll(c.in)
}
