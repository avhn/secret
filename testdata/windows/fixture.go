//go:build windows && windowsfixture

// This hosted-CI fixture is built separately, never shipped or linked into secret.
// Requests (including synthetic values) arrive only on stdin. Errors are fixed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"golang.org/x/sys/windows"
)

type request struct {
	Mode       string
	Executable string
	Args       []string
	Prompt     string
	Value      []byte
	Reference  string
	Path       string
}

type result struct {
	Code   uint32
	Output []byte
	Path   string
	Alias  bool
}

func main() {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" {
		fail()
	}
	var req request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil {
		fail()
	}
	defer secure.Clear(req.Value)
	var got result
	var err error
	switch req.Mode {
	case "console", "get":
		got, err = console(req)
	case "seed":
		err = seed(req)
	case "cleanup":
		err = cleanup()
	case "shortpath":
		var name *uint16
		name, err = windows.UTF16PtrFromString(req.Path)
		if err == nil {
			buffer := make([]uint16, 32768)
			var n uint32
			n, err = windows.GetShortPathName(name, &buffer[0], uint32(len(buffer)))
			if err == nil && n > 0 && n < uint32(len(buffer)) {
				got.Path = windows.UTF16ToString(buffer[:n])
				got.Alias = !strings.EqualFold(filepath.Base(got.Path), filepath.Base(req.Path))
			} else {
				err = errors.New("short path unavailable")
			}
		}
	default:
		err = errors.New("invalid fixture mode")
	}
	if err != nil {
		fail()
	}
	defer secure.Clear(got.Output)
	if json.NewEncoder(os.Stdout).Encode(got) != nil {
		fail()
	}
}

func fail() {
	_, _ = os.Stderr.WriteString("synthetic Windows fixture failed\n")
	os.Exit(1)
}

func console(req request) (result, error) {
	failure := errors.New("disposable console failed")
	if !filepath.IsAbs(req.Executable) || (req.Mode != "get" && req.Prompt == "") || len(req.Value) == 0 || bytes.ContainsAny(req.Value, "\r\n\x00") {
		return result{}, failure
	}
	input, inputWrite, err := os.Pipe()
	if err != nil {
		return result{}, failure
	}
	defer input.Close()
	defer inputWrite.Close()
	outputRead, output, err := os.Pipe()
	if err != nil {
		return result{}, failure
	}
	defer outputRead.Close()
	defer output.Close()
	var terminal windows.Handle
	if windows.CreatePseudoConsole(windows.Coord{X: 240, Y: 40}, windows.Handle(input.Fd()), windows.Handle(output.Fd()), 0, &terminal) != nil {
		return result{}, failure
	}
	// Drain concurrently even during ClosePseudoConsole, which flushes synchronously.
	var mu sync.Mutex
	var captured bytes.Buffer
	overflow := false
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buffer := make([]byte, 4096)
		defer secure.Clear(buffer)
		for {
			n, readErr := outputRead.Read(buffer)
			mu.Lock()
			if captured.Len()+n <= 1<<20 {
				captured.Write(buffer[:n])
			} else {
				overflow = true
			}
			mu.Unlock()
			if readErr != nil {
				return
			}
		}
	}()
	defer func() {
		if terminal != 0 {
			windows.ClosePseudoConsole(terminal)
		}
		outputRead.Close()
		<-drained
		secure.Clear(captured.Bytes())
	}()
	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return result{}, failure
	}
	defer attributes.Delete()
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	ok, _, _ := update.Call(uintptr(unsafe.Pointer(attributes.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(terminal), unsafe.Sizeof(terminal), 0, 0)
	if ok == 0 {
		return result{}, failure
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.ProcThreadAttributeList = attributes.List()
	application, err := windows.UTF16PtrFromString(req.Executable)
	if err != nil {
		return result{}, failure
	}
	line, err := windows.UTF16FromString(windows.ComposeCommandLine(append([]string{req.Executable}, req.Args...)))
	if err != nil {
		return result{}, failure
	}
	var process windows.ProcessInformation
	if windows.CreateProcess(application, &line[0], nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &startup.StartupInfo, &process) != nil {
		return result{}, failure
	}
	windows.CloseHandle(process.Thread)
	defer windows.CloseHandle(process.Process)
	defer windows.TerminateProcess(process.Process, 2)
	input.Close()
	output.Close()
	if req.Mode != "get" {
		deadline := time.Now().Add(20 * time.Second)
		for {
			mu.Lock()
			found := bytes.Contains(captured.Bytes(), []byte(req.Prompt))
			mu.Unlock()
			if found {
				break
			}
			if time.Now().After(deadline) {
				return result{}, failure
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, err = inputWrite.Write(req.Value); err != nil {
			return result{}, failure
		}
		if _, err = inputWrite.Write([]byte{'\r'}); err != nil {
			return result{}, failure
		}
	}
	status, err := windows.WaitForSingleObject(process.Process, 20000)
	var code uint32
	if err != nil || status != windows.WAIT_OBJECT_0 || windows.GetExitCodeProcess(process.Process, &code) != nil {
		return result{}, failure
	}
	// The process is gone; close the console while its output is still drained.
	windows.ClosePseudoConsole(terminal)
	terminal = 0
	<-drained
	mu.Lock()
	defer mu.Unlock()
	if overflow {
		return result{}, failure
	}
	if req.Mode == "get" {
		// A human-terminal get intentionally returns a value. Validate it privately
		// against stdin-supplied bytes, then clear it without returning a transcript.
		if code != 0 || bytes.Count(captured.Bytes(), req.Value) != 1 {
			return result{}, failure
		}
		return result{Code: code}, nil
	}
	return result{Code: code, Output: bytes.Clone(captured.Bytes())}, nil
}

func journalPath() (string, error) {
	root := os.Getenv("RUNNER_TEMP")
	if !filepath.IsAbs(root) || os.Getenv("SECRET_REQUIRE_WINCRED") != "1" {
		return "", errors.New("hosted CredMan gate missing")
	}
	return filepath.Join(root, "secret-windows-cli-targets.jsonl"), nil
}

var credRead = windows.NewLazySystemDLL("advapi32.dll").NewProc("CredReadW")
var credDelete = windows.NewLazySystemDLL("advapi32.dll").NewProc("CredDeleteW")
var credFree = windows.NewLazySystemDLL("advapi32.dll").NewProc("CredFree")

// Probe only an exact synthetic target. Any error other than NOT_FOUND fails.
func absent(target string) bool {
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return false
	}
	var record uintptr
	ok, _, code := credRead.Call(uintptr(unsafe.Pointer(name)), 1, 0, uintptr(unsafe.Pointer(&record)))
	if ok != 0 {
		credFree.Call(record)
		return false
	}
	return code == windows.ERROR_NOT_FOUND
}

func seed(req request) error {
	failure := errors.New("synthetic CredMan seed failed")
	journal, err := journalPath()
	if err != nil || !syntheticTarget("secret/"+strings.TrimPrefix(req.Reference, "wincred:")+"/"+strings.Repeat("0", 32)) || !strings.HasPrefix(req.Reference, "wincred:") || len(req.Value) == 0 {
		return failure
	}
	provider, _, service, err := backend.Dispatch(req.Reference)
	if err != nil {
		return failure
	}
	account, err := store.NewAccount()
	if err != nil {
		return failure
	}
	target := service + "/" + account
	if !absent(target) {
		return failure
	}
	file, err := os.OpenFile(journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return failure
	}
	err = json.NewEncoder(file).Encode(target)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return failure
	}
	// The persistent exact-target journal precedes every write, including errors.
	if provider.Put(service, account, service+"/TOKEN", req.Value) != nil {
		return failure
	}
	got, err := provider.Get(service, account)
	matches := err == nil && bytes.Equal(got, req.Value)
	secure.Clear(got)
	if !matches {
		return failure
	}
	path, err := store.ManifestPath(os.Getenv("SECRETS_DIR"), req.Reference)
	if err != nil {
		return failure
	}
	return store.UpdateManifest(path, "wincred", "TOKEN", nil, account)
}

// Accept only this fixture's random service and exact lower-hex account grammar.
// Never enumerate credentials or accept wildcard, adjacent or legacy namespaces.
func syntheticTarget(target string) bool {
	var identity []string
	for _, name := range []string{"GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB"} {
		value := os.Getenv(name)
		if value == "" {
			return false
		}
		for _, ch := range value {
			if !strings.ContainsRune("0123456789abcdefghijklmnopqrstuvwxyz_-", ch) {
				return false
			}
		}
		identity = append(identity, value)
	}
	prefix := "m5a-cli-" + strings.Join(identity, "-") + "-"
	parts := strings.Split(target, "/")
	if len(parts) != 3 || parts[0] != "secret" || !strings.HasPrefix(parts[1], prefix) {
		return false
	}
	for _, token := range []string{strings.TrimPrefix(parts[1], prefix), parts[2]} {
		if len(token) != 32 {
			return false
		}
		for _, ch := range token {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return false
			}
		}
	}
	return true
}

func cleanup() error {
	journal, err := journalPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(journal)
	if os.IsNotExist(err) {
		return nil // No write is possible without a flushed journal entry.
	}
	if err != nil || len(data) > 1<<20 {
		return errors.New("cannot read exact cleanup journal")
	}
	failed := false
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var target string
		if json.Unmarshal(line, &target) != nil {
			return errors.New("invalid cleanup journal")
		}
		if !syntheticTarget(target) {
			return errors.New("unapproved cleanup target")
		}
		name, _ := windows.UTF16PtrFromString(target)
		ok, _, code := credDelete.Call(uintptr(unsafe.Pointer(name)), 1, 0)
		if ok == 0 && code != windows.ERROR_NOT_FOUND {
			failed = true
		}
		// A separate native read must prove absence even if delete reports success.
		if !absent(target) {
			failed = true
		}
	}
	if failed {
		return errors.New("exact cleanup absence not proved")
	}
	return nil
}
