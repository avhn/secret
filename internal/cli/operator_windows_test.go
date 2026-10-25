//go:build windows

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/transport"
	"golang.org/x/sys/windows"
)

// The native console lane runs only in hosted Windows CI, not against a user's
// interactive console. All input, metadata and paths are disposable synthetic data.
func TestWindowsConsoleConPTY(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
		t.Skip("ConPTY harness runs on windows-latest only")
	}
	for _, mode := range []string{"success", "cancel confirmation", "cancel value", "paste", "overflow", "prompt failure", "input failure", "console event", "piped"} {
		t.Run(mode, func(t *testing.T) { testWindowsConsole(t, mode) })
	}
}

func testWindowsConsole(t *testing.T, mode string) {
	t.Helper()
	input, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer inputWrite.Close()
	outputRead, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputRead.Close()
	defer output.Close()
	var console windows.Handle
	if windows.CreatePseudoConsole(windows.Coord{X: 240, Y: 40}, windows.Handle(input.Fd()), windows.Handle(output.Fd()), 0, &console) != nil {
		t.Fatal("required ConPTY unavailable")
	}
	consoleClosed := false
	defer func() {
		if !consoleClosed {
			windows.ClosePseudoConsole(console)
		}
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer attributes.Delete()
	// PSEUDOCONSOLE is the handle value, not a pointer to that handle.
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	ok, _, _ := update.Call(uintptr(unsafe.Pointer(attributes.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(console), unsafe.Sizeof(console), 0, 0)
	if ok == 0 {
		t.Fatal("cannot attach disposable ConPTY")
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	// Prevent the redirected runner's standard handles from being copied into
	// the child. Null handles let ConPTY initialize its own console handles.
	startup.Flags = windows.STARTF_USESTDHANDLES
	args := []string{os.Args[0], "-test.run=^TestWindowsConsoleHelper$", "-test.v", "--", mode, t.TempDir()}
	line, err := windows.UTF16FromString(windows.ComposeCommandLine(args))
	if err != nil {
		t.Fatal(err)
	}
	application, err := windows.UTF16PtrFromString(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	env, err := transport.WindowsEnvironment(os.Environ())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range env {
			env[i] = 0
		}
	}()
	var process windows.ProcessInformation
	if windows.CreateProcess(application, &line[0], nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &env[0], nil, &startup.StartupInfo, &process) != nil {
		t.Fatal("cannot start disposable console child")
	}
	windows.CloseHandle(process.Thread)
	defer windows.CloseHandle(process.Process)
	defer windows.TerminateProcess(process.Process, 2)
	input.Close()
	output.Close()
	var mu sync.Mutex
	var captured bytes.Buffer
	notify := make(chan struct{}, 1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		var buffer [4096]byte
		for {
			n, err := outputRead.Read(buffer[:])
			mu.Lock()
			if captured.Len()+n <= 1<<20 {
				captured.Write(buffer[:n])
			}
			mu.Unlock()
			select {
			case notify <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() {
		// Drain while ConPTY closes, including failure paths, to avoid its
		// synchronous output-flush shutdown waiting on an unread pipe.
		if !consoleClosed {
			windows.TerminateProcess(process.Process, 2)
			windows.ClosePseudoConsole(console)
			consoleClosed = true
		}
		outputRead.Close()
		<-drained
	}()
	waitFor := func(marker string) {
		t.Helper()
		deadline := time.NewTimer(20 * time.Second)
		defer deadline.Stop()
		for {
			mu.Lock()
			found := bytes.Contains(consoleVisibleText(captured.Bytes()), []byte(marker))
			mu.Unlock()
			if found {
				return
			}
			select {
			case <-notify:
			case <-deadline.C:
				t.Fatal("console prompt/result timed out: " + marker)
			}
		}
	}
	write := func(data []byte) {
		t.Helper()
		if _, err := inputWrite.Write(data); err != nil {
			t.Fatal("synthetic console write failed")
		}
	}
	switch mode {
	case "success", "cancel confirmation", "cancel value":
		waitFor("input hidden")
		// The final prompt proves mode setup completed before synthetic paste.
		waitFor(">")
		if mode == "cancel confirmation" {
			write([]byte{3})
		} else {
			write([]byte("rotate wincred:synthetic-console keys=TOKEN\r"))
			waitFor("New value (hidden):")
			if mode == "cancel value" {
				write([]byte{3})
			} else {
				write([]byte("synthetic-é-𐐷\r"))
			}
		}
	case "paste":
		waitFor("PASTE>")
		write(append(bytes.Repeat([]byte{'s'}, 5000), '\r'))
	case "overflow":
		waitFor("HIDDEN>")
		write([]byte("123456789\r"))
		waitFor("NEXT>")
		write([]byte("next\r"))
	}
	// Do not require the final render before observing exit. ConPTY may buffer
	// that render until shutdown; keep draining while waiting for the helper.
	status, err := windows.WaitForSingleObject(process.Process, 20000)
	var code uint32
	if err != nil || status != windows.WAIT_OBJECT_0 || windows.GetExitCodeProcess(process.Process, &code) != nil || code != 0 {
		t.Fatal("native console child failed or did not exit")
	}
	// Process exit alone need not flush ConPTY's last rendered output. Close it
	// while the reader is still draining, then inspect the complete transcript.
	windows.ClosePseudoConsole(console)
	consoleClosed = true
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("console output did not drain after pseudoconsole close")
	}
	mu.Lock()
	visible := consoleVisibleText(captured.Bytes())
	completed := bytes.Contains(visible, []byte("WINDOWS_CONSOLE_OK"))
	leaked := false
	for _, witness := range [][]byte{[]byte("synthetic-é-𐐷"), []byte("123456789"), bytes.Repeat([]byte{'s'}, 64)} {
		leaked = leaked || bytes.Contains(captured.Bytes(), witness) || bytes.Contains(visible, witness)
	}
	mu.Unlock()
	if leaked {
		t.Fatal("hidden synthetic input echoed")
	}
	if !completed {
		t.Fatal("native console child omitted its completion witness")
	}
}

func TestWindowsConsoleHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "--" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	mode, dir := os.Args[index+1], os.Args[index+2]
	if mode == "piped" {
		input, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		write.Close()
		path := filepath.Join(dir, "never-created")
		var diagnostic bytes.Buffer
		if Main([]string{"rotate", "--audit-dir", path, "invalid", "TOKEN"}, input, os.Stdout, &diagnostic) == 0 || !strings.Contains(diagnostic.String(), secure.ErrTerminalRequired.Error()) {
			t.Fatal("redirected consent did not precede parsing/storage")
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("redirected invocation touched audit persistence")
		}
		fmt.Println("WINDOWS_CONSOLE_OK")
		return
	}
	terminal, err := RequireOperatorTerminal(os.Stdin, os.Stdout)
	if err != nil {
		t.Fatal("native console gate failed")
	}
	defer terminal.Close()
	console := terminal.console.(*controllingConsole)
	var before uint32
	if windows.GetConsoleMode(windows.Handle(console.input.Fd()), &before) != nil {
		t.Fatal("cannot inspect input mode")
	}
	assertMode := func() {
		t.Helper()
		var after uint32
		if windows.GetConsoleMode(windows.Handle(console.input.Fd()), &after) != nil || after != before {
			t.Fatal("console mode not restored exactly")
		}
	}
	switch mode {
	case "success", "cancel confirmation", "cancel value":
		err := terminal.Confirm(OperatorRequest{Action: store.ActionRotate, Target: "wincred:synthetic-console", Keys: []string{"TOKEN"}})
		assertMode()
		if mode == "cancel confirmation" {
			if err != secure.ErrConsent || terminal.confirmed {
				t.Fatal("Ctrl+C confirmed")
			}
		} else {
			if err != nil {
				t.Fatal("exact console confirmation declined")
			}
			value, err := terminal.ReadValue()
			defer secure.Clear(value)
			assertMode()
			if mode == "cancel value" {
				if err != secure.ErrInput || value != nil {
					t.Fatal("Ctrl+C returned a value")
				}
			} else if err != nil || !bytes.Equal(value, []byte("synthetic-é-𐐷")) {
				t.Fatal("native Unicode hidden value changed")
			}
		}
	case "paste":
		value, err := console.readPassword("PASTE> ", operatorValueLimit)
		defer secure.Clear(value)
		assertMode()
		if err != nil || !bytes.Equal(value, bytes.Repeat([]byte{'s'}, 5000)) {
			t.Fatal("native hidden paste was truncated")
		}
	case "overflow":
		value, err := console.readPassword("HIDDEN> ", 8)
		secure.Clear(value)
		assertMode()
		if err != secure.ErrInput {
			t.Fatal("console overflow accepted")
		}
		value, err = console.readPassword("NEXT> ", 8)
		defer secure.Clear(value)
		assertMode()
		if err != nil || !bytes.Equal(value, []byte("next")) {
			t.Fatal("overflow suffix was not drained")
		}
	case "prompt failure":
		console.output.Close()
		if _, err := console.readPassword("FAIL> ", 8); err != secure.ErrTerminal {
			t.Fatal("prompt failure was not fixed")
		}
		assertMode()
		console.output = nil
	case "input failure":
		if _, err := console.readPassword("INVALID> ", 0); err != secure.ErrInput {
			t.Fatal("invalid input was not rejected")
		}
		assertMode()
	case "console event":
		reset := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
		if ok, _, _ := reset.Call(0, 0); ok == 0 {
			t.Fatal("cannot enable disposable console events")
		}
		go func() {
			time.Sleep(200 * time.Millisecond)
			_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0)
		}()
		if _, err := console.readPassword("EVENT> ", 8); err != secure.ErrInput {
			t.Fatal("console event did not cancel input")
		}
		assertMode()
	default:
		t.Fatal("unknown synthetic console mode")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal("owned console close failed")
	}
	fmt.Println("WINDOWS_CONSOLE_OK")
}

// Keep a compile-time check on the reader contract and native union layout.
var _ io.Reader = (*consoleReader)(nil)

func TestWindowsConsoleInputLayout(t *testing.T) {
	if unsafe.Sizeof(consoleInputRecord{}) != 20 || unsafe.Offsetof(consoleInputRecord{}.char) != 14 {
		t.Fatal("INPUT_RECORD layout mismatch")
	}
}
