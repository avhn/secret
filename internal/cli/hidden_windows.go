//go:build windows

package cli

import (
	"os"
	"os/signal"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

// INPUT_RECORD contains a 4-byte header followed by the 16-byte KEY_EVENT_RECORD
// union. No native input is converted to a Go string or included in diagnostics.
type consoleInputRecord struct {
	kind                    uint16
	padding                 uint16
	down                    int32
	repeat, key, scan, char uint16
	control                 uint32
}

type consoleReader struct {
	handle     windows.Handle
	signals    <-chan os.Signal
	pending    [utf8.UTFMax]byte
	start, end int
	repeat     uint16
	unit       uint16
}

func (reader *consoleReader) nextUnit() (uint16, error) {
	for {
		select {
		case <-reader.signals:
			return 0, secure.ErrInput
		default:
		}
		if reader.repeat > 0 {
			reader.repeat--
			return reader.unit, nil
		}
		status, err := windows.WaitForSingleObject(reader.handle, 25)
		if err != nil {
			return 0, secure.ErrInput
		}
		if status == uint32(windows.WAIT_TIMEOUT) {
			continue
		}
		if status != windows.WAIT_OBJECT_0 {
			return 0, secure.ErrInput
		}
		var record consoleInputRecord
		var count uint32
		ok, _, _ := readConsoleInput.Call(uintptr(reader.handle), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
		if ok == 0 || count != 1 {
			clearRecord(&record)
			return 0, secure.ErrInput
		}
		unit, repeat, accepted := recordUnit(&record)
		clearRecord(&record)
		if !accepted {
			continue
		}
		reader.unit, reader.repeat = unit, repeat
		return reader.unit, nil
	}
}

func clearRecord(record *consoleInputRecord) { *record = consoleInputRecord{} }

// recordUnit returns one UTF-16 unit and its remaining repeats. Characters outside
// the keyboard layout (Alt+Numpad entry, including ConPTY-synthesized input) are
// delivered once, on the Alt key-up record; other key-up records carry no input.
func recordUnit(record *consoleInputRecord) (uint16, uint16, bool) {
	if record.kind != 1 || record.char == 0 {
		return 0, 0, false
	}
	if record.down == 0 {
		if record.key != windows.VK_MENU {
			return 0, 0, false
		}
		return record.char, 0, true
	}
	if record.repeat == 0 {
		return 0, 0, false
	}
	return record.char, record.repeat - 1, true
}

func (reader *consoleReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if reader.start == reader.end {
		unit, err := reader.nextUnit()
		if err != nil {
			return 0, err
		}
		r := rune(unit)
		if unit >= 0xd800 && unit <= 0xdbff {
			next, err := reader.nextUnit()
			if err != nil || next < 0xdc00 || next > 0xdfff {
				return 0, secure.ErrInput
			}
			r = utf16.DecodeRune(r, rune(next))
		} else if unit >= 0xdc00 && unit <= 0xdfff {
			return 0, secure.ErrInput
		}
		reader.start, reader.end = 0, utf8.EncodeRune(reader.pending[:], r)
	}
	n := copy(data, reader.pending[reader.start:reader.end])
	clear(reader.pending[reader.start : reader.start+n])
	reader.start += n
	return n, nil
}

func (console *controllingConsole) readPassword(prompt string, limit int) (value []byte, err error) {
	if console.input == nil || console.output == nil {
		return nil, secure.ErrTerminal
	}
	handle := windows.Handle(console.input.Fd())
	var before uint32
	if windows.GetConsoleMode(handle, &before) != nil {
		return nil, secure.ErrTerminal
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	// Ctrl+C becomes a raw key rather than process termination. Externally sent
	// catchable console events use the signal channel; polling never strands a
	// blocking ReadConsole call, so restoration also runs on cancellation/errors.
	quiet := before &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_VIRTUAL_TERMINAL_INPUT)
	if windows.SetConsoleMode(handle, quiet) != nil {
		return nil, secure.ErrTerminal
	}
	defer func() {
		if windows.SetConsoleMode(handle, before) != nil {
			err = secure.ErrTerminal
		}
		if err != nil {
			secure.Clear(value)
			value = nil
		}
	}()
	if _, err := console.Write([]byte(prompt)); err != nil {
		return nil, secure.ErrTerminal
	}
	reader := &consoleReader{handle: handle, signals: signals}
	defer func() { clear(reader.pending[:]); reader.unit, reader.repeat = 0, 0 }()
	return readOperatorLine(reader, limit)
}

// Stash uses the same verified console and restoration path on Windows. The
// operator boundary separately checks stdout as well, before metadata access.
func windowsHiddenInput(in *os.File, prompt string) ([]byte, error) {
	if !windowsConsoleFile(in) {
		return nil, secure.ErrTerminalRequired
	}
	console, err := openWindowsConsole()
	if err != nil {
		return nil, err
	}
	defer console.Close()
	value, err := console.readPassword(prompt, operatorValueLimit)
	_, writeErr := console.Write([]byte("\n"))
	if err != nil || writeErr != nil {
		secure.Clear(value)
		return nil, secure.ErrInput
	}
	return value, nil
}

func requireStashInput(in *os.File) error {
	if !windowsConsoleFile(in) {
		return secure.ErrTerminalRequired
	}
	return nil
}

func (c command) input(key string) ([]byte, error) { return windowsHiddenInput(c.in, key+": ") }
