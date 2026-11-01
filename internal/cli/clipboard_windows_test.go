//go:build windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type fakeClipboard struct {
	values                        map[uint32][]byte
	formats                       []string
	borrowed, snapshot            []byte
	busy, opens, closes, destroys int
	empties                       int
	opened                        bool
	fail                          string
}

func (f *fakeClipboard) owner() (uintptr, error) {
	if f.fail == "owner" {
		return 0, errors.New("synthetic private failure")
	}
	return 1, nil
}
func (f *fakeClipboard) destroy(uintptr) { f.destroys++ }
func (f *fakeClipboard) open(owner uintptr) error {
	f.opens++
	if f.opens <= f.busy || owner != 1 {
		return errors.New("synthetic busy")
	}
	f.opened = true
	return nil
}
func (f *fakeClipboard) close() error {
	f.closes++
	f.opened = false
	if f.fail == "close" {
		return errors.New("synthetic private failure")
	}
	return nil
}
func (f *fakeClipboard) empty() error {
	if !f.opened || f.fail == "empty" {
		return errors.New("synthetic private failure")
	}
	f.empties++
	f.values = make(map[uint32][]byte)
	return nil
}
func (f *fakeClipboard) register(name string) (uint32, error) {
	if f.fail == "register" {
		return 0, errors.New("synthetic private failure")
	}
	f.formats = append(f.formats, name)
	return uint32(0xc000 + len(f.formats)), nil
}
func (f *fakeClipboard) set(format uint32, value []byte) error {
	if !f.opened || f.fail == "set" || f.fail == "text" && format == clipboardUnicodeText {
		return errors.New("synthetic private failure")
	}
	f.values[format] = bytes.Clone(value)
	if format == clipboardUnicodeText {
		f.borrowed = value
	}
	return nil
}
func (f *fakeClipboard) data(format uint32, limit int) ([]byte, error) {
	if !f.opened || f.fail == "data" {
		// An API may return bytes together with an error. They still need wiping.
		f.snapshot = []byte("synthetic partial")
		return f.snapshot, errors.New("synthetic private failure")
	}
	value := f.values[format]
	f.snapshot = bytes.Clone(value[:min(len(value), limit)])
	return f.snapshot, nil
}

// Resolve entry points only. This does not open or inspect the local clipboard.
func TestWindowsClipboardNativeAPIs(t *testing.T) {
	for _, proc := range []*windows.LazyProc{
		clipboardCreate, clipboardDestroy, clipboardOpen, clipboardClose,
		clipboardEmpty, clipboardSet, clipboardGet, clipboardFormat,
		clipboardAlloc, clipboardFree, clipboardLock, clipboardUnlock,
		clipboardSize, clipboardMove, clipboardZero,
	} {
		if proc.Find() != nil {
			t.Fatal("required Windows clipboard entry point unavailable")
		}
	}
}

func TestWindowsClipboardUTF16(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
		want  []byte
	}{
		{"empty", nil, []byte{0, 0}},
		{"ascii", []byte("synthetic"), []byte{'s', 0, 'y', 0, 'n', 0, 't', 0, 'h', 0, 'e', 0, 't', 0, 'i', 0, 'c', 0, 0, 0}},
		{"bmp", []byte{0xc3, 0xa9}, []byte{0xe9, 0, 0, 0}},
		{"non-bmp", []byte{0xf0, 0x9f, 0x94, 0x90}, []byte{0x3d, 0xd8, 0x10, 0xdd, 0, 0}},
		{"max-rune", []byte{0xf4, 0x8f, 0xbf, 0xbf}, []byte{0xff, 0xdb, 0xff, 0xdf, 0, 0}},
		{"replacement-rune", []byte{0xef, 0xbf, 0xbd}, []byte{0xfd, 0xff, 0, 0}},
		{"line-endings", []byte{'a', '\r', '\n', 'b', '\n'}, []byte{'a', 0, '\r', 0, '\n', 0, 'b', 0, '\n', 0, 0, 0}},
		{"nul", []byte{'a', 0, 'b'}, nil},
		{"trailing-nul", []byte{'a', 0}, nil},
		{"invalid", []byte{0xff}, nil},
		{"truncated", []byte{0xe2, 0x82}, nil},
		{"surrogate", []byte{0xed, 0xa0, 0x80}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := clipboardUTF16(tc.value)
			defer clear(got)
			if !bytes.Equal(got, tc.want) || (err != nil) != (tc.want == nil) {
				t.Fatal("UTF-16 conversion result mismatch")
			}
			f := &fakeClipboard{}
			c := windowsClipboard{api: f}
			if err != nil {
				if c.copy(tc.value) != errClipboard || c.clearIfUnchanged(tc.value) != errClipboard || f.opens != 0 {
					t.Fatal("invalid value reached the clipboard")
				}
			} else if c.copy(tc.value) != nil || c.clearIfUnchanged(tc.value) != nil || f.empties != 2 {
				t.Fatal("Unicode value did not round trip through conditional clearing")
			}
		})
	}
}

func TestWindowsClipboardCopy(t *testing.T) {
	f := &fakeClipboard{}
	c := windowsClipboard{api: f}
	value := []byte("synthetic")
	if err := c.copy(value); err != nil {
		t.Fatal("copy failed")
	}
	want, _ := clipboardUTF16(value)
	defer clear(want)
	if !bytes.Equal(f.values[clipboardUnicodeText], want) || !bytes.Equal(value, []byte("synthetic")) {
		t.Fatal("copy changed the value")
	}
	if !bytes.Equal(f.borrowed, make([]byte, len(f.borrowed))) {
		t.Fatal("UTF-16 intermediate was not zeroed")
	}
	if !reflect.DeepEqual(f.formats, []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"}) {
		t.Fatal("history/cloud exclusion formats missing")
	}
	for format, data := range f.values {
		if format != clipboardUnicodeText && !bytes.Equal(data, []byte{0, 0, 0, 0}) {
			t.Fatal("history/cloud policy was not disabled")
		}
	}
	if f.empties != 1 || f.closes != 1 || f.destroys != 1 || f.opened {
		t.Fatal("clipboard lifetime mismatch")
	}
}

func TestWindowsClipboardConditionalClear(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current []byte
		clear   bool
	}{
		{"unchanged", []byte{'a', 0, 0, 0}, true},
		{"allocation-padding", []byte{'a', 0, 0, 0, 0xaa, 0xbb}, true},
		{"changed", []byte{'b', 0, 0, 0}, false},
		{"prefix", []byte{'a', 0, 'b', 0, 0, 0}, false},
		{"empty", []byte{0, 0}, false},
		{"missing", nil, false},
		{"unterminated", []byte{'a', 0}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeClipboard{values: map[uint32][]byte{clipboardUnicodeText: bytes.Clone(tc.current)}}
			if err := (windowsClipboard{api: f}).clearIfUnchanged([]byte{'a'}); err != nil {
				t.Fatal("conditional clear failed")
			}
			if (f.empties == 1) != tc.clear || f.opened || f.closes != 1 || f.destroys != 1 {
				t.Fatal("conditional clear or lifetime mismatch")
			}
			if !tc.clear && !bytes.Equal(f.values[clipboardUnicodeText], tc.current) {
				t.Fatal("replacement clipboard contents changed")
			}
			if !bytes.Equal(f.snapshot, make([]byte, len(f.snapshot))) {
				t.Fatal("comparison snapshot was not zeroed")
			}
		})
	}
}

func TestWindowsClipboardBusy(t *testing.T) {
	for _, busy := range []int{0, 3, 10} {
		f := &fakeClipboard{busy: busy}
		var delays []time.Duration
		c := windowsClipboard{api: f, sleep: func(d time.Duration) { delays = append(delays, d) }}
		err := c.copy([]byte("synthetic"))
		if (err != nil) != (busy == 10) || f.opens != min(busy+1, 10) || len(delays) != min(busy, 9) {
			t.Fatal("clipboard retry bound mismatch")
		}
		for i, delay := range delays {
			if delay != min(5*time.Millisecond<<i, 160*time.Millisecond) {
				t.Fatal("clipboard retry backoff mismatch")
			}
		}
		if busy == 10 && (f.empties != 0 || f.closes != 0) || f.destroys != 1 {
			t.Fatal("busy clipboard was modified or owner leaked")
		}
	}
}

func TestWindowsClipboardFailures(t *testing.T) {
	for _, fail := range []string{"owner", "register", "empty", "set", "text", "close", "data"} {
		t.Run(fail, func(t *testing.T) {
			f := &fakeClipboard{fail: fail}
			c := windowsClipboard{api: f}
			var err error
			if fail == "data" {
				err = c.clearIfUnchanged([]byte("synthetic"))
			} else {
				err = c.copy([]byte("synthetic"))
			}
			if err != errClipboard || err.Error() != "clipboard copy failed" {
				t.Fatal("clipboard error was not fixed")
			}
			if f.opened || fail != "owner" && (f.closes != 1 || f.destroys != 1) {
				t.Fatal("clipboard error leaked its lifetime")
			}
			if fail == "register" && f.empties != 0 {
				t.Fatal("registration failure changed clipboard contents")
			}
			if !bytes.Equal(f.snapshot, make([]byte, len(f.snapshot))) {
				t.Fatal("partial comparison snapshot was not zeroed")
			}
		})
	}
}

func TestWindowsClipboardClearStartFallback(t *testing.T) {
	wrappedDenied := &os.PathError{Op: "synthetic start", Path: "synthetic.exe", Err: windows.ERROR_ACCESS_DENIED}
	otherError := errors.New("synthetic start failure")
	for _, tc := range []struct {
		name   string
		errors []error
	}{
		{"breakaway-success", []error{nil}},
		{"breakaway-denied-fallback-success", []error{wrappedDenied, nil}},
		{"other-error-no-fallback", []error{otherError}},
		{"fallback-failed", []error{wrappedDenied, otherError}},
		{"both-denied", []error{wrappedDenied, wrappedDenied}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts []*exec.Cmd
			cmd, err := startClipboardClearProcess(`C:\synthetic path\secret.exe`, 45, os.Stdin, func(cmd *exec.Cmd) error {
				attempt := len(attempts)
				attempts = append(attempts, cmd)
				if attempt >= len(tc.errors) {
					t.Fatal("unexpected clearer launch retry")
				}
				flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
				if attempt == 0 {
					flags |= windows.CREATE_BREAKAWAY_FROM_JOB
				}
				if cmd.SysProcAttr.CreationFlags != flags || !cmd.SysProcAttr.HideWindow || cmd.Stdin != os.Stdin {
					t.Fatal("clearer launch flags or inherited input mismatch")
				}
				if !reflect.DeepEqual(cmd.Args, []string{`C:\synthetic path\secret.exe`, "--clipboard-clear", "45"}) || cmd.Stdout != nil || cmd.Stderr != nil {
					t.Fatal("clearer retry changed argv or inherited output handles")
				}
				return tc.errors[attempt]
			})
			if len(attempts) != len(tc.errors) || err != tc.errors[len(tc.errors)-1] || cmd != attempts[len(attempts)-1] {
				t.Fatal("clearer retry selection or error mismatch")
			}
			if len(attempts) == 2 && attempts[0] == attempts[1] {
				t.Fatal("fallback reused a failed command's handles")
			}
		})
	}
}

func TestWindowsClipboardClearCommand(t *testing.T) {
	cmd := clipboardClearCommand(`C:\synthetic path\secret.exe`, 45, true)
	if !reflect.DeepEqual(cmd.Args, []string{`C:\synthetic path\secret.exe`, "--clipboard-clear", "45"}) {
		t.Fatal("clearer argv must contain only executable, mode and timeout")
	}
	if cmd.SysProcAttr.CreationFlags != windows.DETACHED_PROCESS|windows.CREATE_NEW_PROCESS_GROUP|windows.CREATE_BREAKAWAY_FROM_JOB || !cmd.SysProcAttr.HideWindow {
		t.Fatal("clearer must detach and request Job breakaway")
	}
	if cmd.Stdout != nil || cmd.Stderr != nil || cmd.Env != nil {
		t.Fatal("clearer must not capture parent output or export a value")
	}
}
