//go:build windows

package cli

import (
	"io"
	"os"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

type controllingConsole struct{ input, output *os.File }

// RequireOperatorTerminal rejects redirected stdin AND stdout before opening
// CONIN$/CONOUT$, discovering metadata or reaching any provider or filesystem.
func RequireOperatorTerminal(in *os.File, out io.Writer) (*OperatorTerminal, error) {
	return requireOperatorTerminal(in, out, operatorTerminalOps{
		isTerminal: windowsConsoleFile,
		open:       openWindowsConsole,
	})
}

func windowsConsoleFile(file *os.File) bool {
	var mode uint32
	return file != nil && windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil
}

func openWindowsConsole() (operatorConsole, error) {
	input, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if err != nil {
		return nil, secure.ErrTerminal
	}
	output, err := os.OpenFile("CONOUT$", os.O_RDWR, 0)
	if err != nil {
		input.Close()
		return nil, secure.ErrTerminal
	}
	console := &controllingConsole{input: input, output: output}
	if !windowsConsoleFile(input) || !windowsConsoleFile(output) {
		console.Close()
		return nil, secure.ErrTerminal
	}
	return console, nil
}

// Only names-only prompts/newlines are written here. Console W APIs avoid the
// ambient OEM/ANSI code page for both displayed identities and hidden values.
func (console *controllingConsole) Write(data []byte) (int, error) {
	if console.output == nil || !utf8.Valid(data) {
		return 0, secure.ErrTerminal
	}
	var wide []uint16
	for rest := data; len(rest) != 0; {
		r, n := utf8.DecodeRune(rest)
		if r == '\n' {
			wide = append(wide, '\r')
		}
		if r <= 0xffff {
			wide = append(wide, uint16(r))
		} else {
			hi, lo := utf16.EncodeRune(r)
			wide = append(wide, uint16(hi), uint16(lo))
		}
		rest = rest[n:]
	}
	owned := wide
	defer func() {
		for i := range owned {
			owned[i] = 0
		}
	}()
	for len(wide) > 0 {
		var written uint32
		if windows.WriteConsole(windows.Handle(console.output.Fd()), &wide[0], uint32(len(wide)), &written, nil) != nil || written == 0 || written > uint32(len(wide)) {
			return 0, secure.ErrTerminal
		}
		wide = wide[written:]
	}
	return len(data), nil
}

func (console *controllingConsole) Close() error {
	var err error
	for _, file := range []*os.File{console.input, console.output} {
		if file != nil && file.Close() != nil {
			err = secure.ErrTerminal
		}
	}
	console.input, console.output = nil, nil
	return err
}
