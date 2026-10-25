//go:build !windows

package cli

import (
	"github.com/avhn/secret/internal/secure"
	"golang.org/x/term"
	"io"
	"os"
	"strings"
)

type controllingConsole struct{ *os.File }

func (console controllingConsole) readPassword(prompt string, limit int) (value []byte, err error) {
	state, err := term.MakeRaw(int(console.Fd()))
	if err != nil {
		return nil, secure.ErrTerminal
	}
	defer func() {
		if term.Restore(int(console.Fd()), state) != nil {
			err = secure.ErrTerminal
		}
		if err != nil {
			secure.Clear(value)
			value = nil
		}
	}()
	// Disable canonical buffering before displaying the prompt: even a pasted
	// line must not pass through the kernel's silently truncating line buffer.
	// Raw mode also disables output translation, so render prompt line endings.
	if _, err := io.WriteString(console, strings.ReplaceAll(prompt, "\n", "\r\n")); err != nil {
		return nil, secure.ErrTerminal
	}
	return readOperatorLine(console.File, limit)
}

// RequireOperatorTerminal checks stdin AND stdout before opening the controlling
// terminal. Call it before resolving, statting, opening or listing any store, or
// invoking a provider. After this gate, callers may discover names-only metadata
// to construct a request, but must Confirm before fetching/moving values or
// mutating anything. There are no bypass flags, piped confirmations or JSON mode.
// Native console handles are opened only after both checks succeed.

func RequireOperatorTerminal(in *os.File, out io.Writer) (*OperatorTerminal, error) {
	return requireOperatorTerminal(in, out, operatorTerminalOps{
		isTerminal: func(file *os.File) bool { return term.IsTerminal(int(file.Fd())) },
		open: func() (operatorConsole, error) {
			file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return nil, secure.ErrTerminal
			}
			if !term.IsTerminal(int(file.Fd())) {
				_ = file.Close()
				return nil, secure.ErrTerminal
			}
			return controllingConsole{file}, nil
		},
	})
}
