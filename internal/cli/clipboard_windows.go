//go:build windows

package cli

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

const clipboardUnicodeText = 13 // CF_UNICODETEXT

var errClipboard = errors.New("clipboard copy failed")

// Only system DLLs are used. x/sys/windows does not wrap the clipboard APIs.
var (
	clipboardUser32  = windows.NewLazySystemDLL("user32.dll")
	clipboardKernel  = windows.NewLazySystemDLL("kernel32.dll")
	clipboardCreate  = clipboardUser32.NewProc("CreateWindowExW")
	clipboardDestroy = clipboardUser32.NewProc("DestroyWindow")
	clipboardOpen    = clipboardUser32.NewProc("OpenClipboard")
	clipboardClose   = clipboardUser32.NewProc("CloseClipboard")
	clipboardEmpty   = clipboardUser32.NewProc("EmptyClipboard")
	clipboardSet     = clipboardUser32.NewProc("SetClipboardData")
	clipboardGet     = clipboardUser32.NewProc("GetClipboardData")
	clipboardFormat  = clipboardUser32.NewProc("RegisterClipboardFormatW")
	clipboardAlloc   = clipboardKernel.NewProc("GlobalAlloc")
	clipboardFree    = clipboardKernel.NewProc("GlobalFree")
	clipboardLock    = clipboardKernel.NewProc("GlobalLock")
	clipboardUnlock  = clipboardKernel.NewProc("GlobalUnlock")
	clipboardSize    = clipboardKernel.NewProc("GlobalSize")
	clipboardMove    = clipboardKernel.NewProc("RtlMoveMemory")
	clipboardZero    = clipboardKernel.NewProc("RtlZeroMemory")
)

// set copies bytes into a movable native allocation and transfers it only on
// success. data returns an owned, bounded snapshot, never borrowed native memory.
// Tests inject this interface without opening the session clipboard.
type windowsClipboardAPI interface {
	owner() (uintptr, error)
	destroy(uintptr)
	open(uintptr) error
	close() error
	empty() error
	register(string) (uint32, error)
	set(uint32, []byte) error
	data(uint32, int) ([]byte, error)
}

type windowsClipboard struct {
	api   windowsClipboardAPI
	sleep func(time.Duration)
}

func copyClipboard(value []byte) error {
	return (windowsClipboard{api: nativeClipboard{}, sleep: time.Sleep}).copy(value)
}

func clearClipboardIfUnchanged(value []byte) {
	_ = (windowsClipboard{api: nativeClipboard{}, sleep: time.Sleep}).clearIfUnchanged(value)
}

// Open/close, the hidden owner window and its destruction must stay on the same
// thread. OpenClipboard(NULL) is not sufficient: EmptyClipboard would leave a
// NULL owner, causing SetClipboardData to fail. No delayed rendering is used.
func (c windowsClipboard) withOpen(action func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	owner, err := c.api.owner()
	if err != nil {
		return errClipboard
	}
	defer c.api.destroy(owner)
	for attempt := 0; ; attempt++ {
		if c.api.open(owner) == nil {
			break
		}
		if attempt == 9 {
			return errClipboard
		}
		c.sleep(min(5*time.Millisecond<<attempt, 160*time.Millisecond))
	}
	defer func() {
		if c.api.close() != nil {
			err = errClipboard
		}
	}()
	if action() != nil {
		return errClipboard
	}
	return nil
}

// clipboardUTF16 encodes directly from UTF-8 bytes to UTF-16LE bytes, including
// the terminating NUL. Invalid UTF-8 and embedded NUL fail rather than truncate
// or replace value bytes. There are no Go string or rune-slice value copies.
func clipboardUTF16(value []byte) ([]byte, error) {
	if !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return nil, errClipboard
	}
	wide := make([]byte, 0, 2*len(value)+2)
	for len(value) != 0 {
		r, size := utf8.DecodeRune(value)
		value = value[size:]
		if r > 0xffff {
			hi, lo := utf16.EncodeRune(r)
			wide = binary.LittleEndian.AppendUint16(wide, uint16(hi))
			wide = binary.LittleEndian.AppendUint16(wide, uint16(lo))
		} else {
			wide = binary.LittleEndian.AppendUint16(wide, uint16(r))
		}
	}
	return binary.LittleEndian.AppendUint16(wide, 0), nil
}

func (c windowsClipboard) copy(value []byte) error {
	wide, err := clipboardUTF16(value)
	if err != nil {
		return errClipboard
	}
	defer secure.Clear(wide)
	return c.withOpen(func() error {
		// Register all policy formats before changing any clipboard contents.
		// These are requests to cooperating Windows history/cloud consumers,
		// not protection against another clipboard reader or a remote session.
		var formats [3]uint32
		for i, name := range []string{
			"ExcludeClipboardContentFromMonitorProcessing",
			"CanIncludeInClipboardHistory",
			"CanUploadToCloudClipboard",
		} {
			formats[i], err = c.api.register(name)
			if err != nil {
				return errClipboard
			}
		}
		if c.api.empty() != nil {
			return errClipboard
		}
		for _, format := range formats {
			if c.api.set(format, []byte{0, 0, 0, 0}) != nil {
				_ = c.api.empty()
				return errClipboard
			}
		}
		if c.api.set(clipboardUnicodeText, wide) != nil {
			_ = c.api.empty()
			return errClipboard
		}
		return nil
	})
}

func (c windowsClipboard) clearIfUnchanged(value []byte) error {
	wide, err := clipboardUTF16(value)
	if err != nil {
		return errClipboard
	}
	defer secure.Clear(wide)
	return c.withOpen(func() error {
		// Read only enough bytes to compare the expected value and terminator.
		// GlobalSize may include allocation padding. Bytes after the first NUL
		// are not text. Holding OpenClipboard across comparison and emptying
		// prevents another writer's replacement from being cleared in between.
		current, err := c.api.data(clipboardUnicodeText, len(wide))
		defer secure.Clear(current)
		if err != nil {
			return errClipboard
		}
		if len(current) == len(wide) && bytes.Equal(current, wide) {
			return c.api.empty()
		}
		return nil
	})
}

// startClipboardClear mirrors the Unix pipe-fed, post-exit helper. Detachment
// avoids parent-console events. Try Job breakaway, but retry without it when
// denied. The fallback remains subject to enclosing Jobs, including run/exec's
// kill-on-close Job, so it cannot guarantee post-parent-exit clearing.
// Only the timeout enters argv. No value file, shell or PowerShell is involved.
func startClipboardClear(value []byte, seconds int) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	defer read.Close()
	cmd, err := startClipboardClearProcess(executable, seconds, read, (*exec.Cmd).Start)
	if err != nil {
		write.Close()
		return errors.New("clipboard clear setup failed")
	}
	read.Close()
	n, err := write.Write(value)
	closeErr := write.Close()
	_ = cmd.Process.Release()
	if err != nil || closeErr != nil || n != len(value) {
		return errors.New("clipboard clear setup failed")
	}
	return nil
}

// A failed Start may close its temporary handles. Construct a fresh command for
// fallback, borrowing only the caller-owned input pipe again. Never retry other
// errors or modify the enclosing Job's containment policy.
func startClipboardClearProcess(executable string, seconds int, input *os.File, start func(*exec.Cmd) error) (*exec.Cmd, error) {
	cmd := clipboardClearCommand(executable, seconds, true)
	cmd.Stdin = input
	err := start(cmd)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		cmd = clipboardClearCommand(executable, seconds, false)
		cmd.Stdin = input
		err = start(cmd)
	}
	return cmd, err
}

func clipboardClearCommand(executable string, seconds int, breakaway bool) *exec.Cmd {
	cmd := exec.Command(executable, "--clipboard-clear", strconv.Itoa(seconds))
	flags := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	if breakaway {
		flags |= windows.CREATE_BREAKAWAY_FROM_JOB
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
	return cmd
}

type nativeClipboard struct{}

func (nativeClipboard) owner() (uintptr, error) {
	// STATIC is a system-registered class. A hidden popup needs no custom window
	// procedure or message pump for synchronous, non-delayed clipboard data.
	class, _ := windows.UTF16PtrFromString("STATIC")
	owner, _, _ := clipboardCreate.Call(0, uintptr(unsafe.Pointer(class)), 0, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0)
	runtime.KeepAlive(class)
	if owner == 0 {
		return 0, errClipboard
	}
	return owner, nil
}

func (nativeClipboard) destroy(owner uintptr) { clipboardDestroy.Call(owner) }

func (nativeClipboard) open(owner uintptr) error {
	ok, _, _ := clipboardOpen.Call(owner)
	if ok == 0 {
		return errClipboard
	}
	return nil
}

func (nativeClipboard) close() error {
	ok, _, _ := clipboardClose.Call()
	if ok == 0 {
		return errClipboard
	}
	return nil
}

func (nativeClipboard) empty() error {
	ok, _, _ := clipboardEmpty.Call()
	if ok == 0 {
		return errClipboard
	}
	return nil
}

func (nativeClipboard) register(name string) (uint32, error) {
	wide, err := windows.UTF16PtrFromString(name) // public format name only
	if err != nil {
		return 0, errClipboard
	}
	format, _, _ := clipboardFormat.Call(uintptr(unsafe.Pointer(wide)))
	runtime.KeepAlive(wide)
	if format == 0 {
		return 0, errClipboard
	}
	return uint32(format), nil
}

func (nativeClipboard) set(format uint32, data []byte) error {
	if len(data) == 0 {
		return errClipboard
	}
	memory, _, _ := clipboardAlloc.Call(0x0042, uintptr(len(data))) // GMEM_MOVEABLE | GMEM_ZEROINIT
	if memory == 0 {
		return errClipboard
	}
	address, _, _ := clipboardLock.Call(memory)
	if address == 0 {
		clipboardFree.Call(memory)
		return errClipboard
	}
	// Native copies avoid converting a syscall-returned address into a Go
	// pointer/slice. The synchronous call borrows the owned Go bytes only here.
	clipboardMove.Call(address, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	runtime.KeepAlive(data)
	clipboardUnlock.Call(memory)
	published, _, _ := clipboardSet.Call(uintptr(format), memory)
	if published == 0 {
		address, _, _ = clipboardLock.Call(memory)
		if address != 0 {
			clipboardZero.Call(address, uintptr(len(data)))
			clipboardUnlock.Call(memory)
		}
		clipboardFree.Call(memory)
		return errClipboard
	}
	// Ownership belongs to Windows now. Do not free or mutate the allocation.
	return nil
}

func (nativeClipboard) data(format uint32, limit int) ([]byte, error) {
	memory, _, _ := clipboardGet.Call(uintptr(format))
	if memory == 0 || limit <= 0 {
		return nil, errClipboard
	}
	size, _, _ := clipboardSize.Call(memory)
	if size == 0 {
		return nil, errClipboard
	}
	address, _, _ := clipboardLock.Call(memory)
	if address == 0 {
		return nil, errClipboard
	}
	defer clipboardUnlock.Call(memory)
	data := make([]byte, int(min(size, uintptr(limit))))
	clipboardMove.Call(uintptr(unsafe.Pointer(&data[0])), address, uintptr(len(data)))
	runtime.KeepAlive(data)
	return data, nil
}
