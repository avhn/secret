//go:build windows && windowsfixture

// This hosted-CI fixture is built separately, never shipped or linked into secret.
// Requests (including synthetic values) arrive only on stdin. Errors are fixed.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	// These value-free subprocess modes are synthetic lifecycle fixtures only.
	if len(os.Args) >= 2 && os.Args[1] == "launcher-child" {
		launcherChild(os.Args[2:])
		fail()
	}
	if len(os.Args) >= 2 && os.Args[1] == "launcher-host" {
		launcherHost(os.Args[2:])
		fail()
	}
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
	case "launcher":
		got, err = launcherLifecycle(req)
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
		if req.Mode == "console" || req.Mode == "get" || req.Mode == "launcher" {
			// Console errors contain fixed stage names only, never captured
			// output, native error text, request data or synthetic values.
			_, _ = fmt.Fprintln(os.Stderr, err)
		}
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

// ConPTY is a rendered screen stream, not a byte-for-byte WriteConsole log.
// Its VT renderer may move the cursor rather than emit trailing blank cells.
func consolePromptSeen(output []byte, prompt string) bool {
	marker := strings.TrimRight(prompt, " \t\r\n")
	return marker != "" && bytes.Contains(output, []byte(marker))
}

func console(req request) (result, error) {
	failure := errors.New("disposable console failed")
	if !filepath.IsAbs(req.Executable) || (req.Mode != "get" && strings.TrimSpace(req.Prompt) == "") || len(req.Value) == 0 || bytes.ContainsAny(req.Value, "\r\n\x00") {
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
	// STARTF_USESTDHANDLES with null handles suppresses the redirected host
	// handle copies. ConPTY initializes the child console handles instead.
	// Do not pass the host's pipes or loosen the product's terminal gate.
	startup.StartupInfo.Flags |= windows.STARTF_USESTDHANDLES
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
		return result{}, errors.New("disposable console process creation failed")
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
			found := consolePromptSeen(captured.Bytes(), req.Prompt)
			mu.Unlock()
			if found {
				break
			}
			if status, err := windows.WaitForSingleObject(process.Process, 0); err != nil || status == windows.WAIT_OBJECT_0 {
				return result{}, errors.New("disposable console exited before prompt")
			}
			if time.Now().After(deadline) {
				return result{}, errors.New("disposable console prompt wait failed")
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
		return result{}, errors.New("disposable console process wait failed")
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
			return result{}, errors.New("disposable console get verification failed")
		}
		return result{Code: code}, nil
	}
	return result{Code: code, Output: bytes.Clone(captured.Bytes())}, nil
}

// Publish readiness identities only after their complete decimal bytes are closed.
func writeLauncherPID(path string, pid int) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".pid-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.WriteString(strconv.Itoa(pid))
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(file.Name(), path)
}

// launcherChild never receives a value in argv and never emits its environment.
func launcherChild(args []string) {
	if len(args) != 2 || !filepath.IsAbs(args[1]) {
		fail()
	}
	mode, dir := args[0], args[1]
	if mode == "descendant" {
		if writeLauncherPID(filepath.Join(dir, "descendant.pid"), os.Getpid()) != nil {
			fail()
		}
		for {
			time.Sleep(time.Second)
		}
	}
	if !bytes.Equal([]byte(os.Getenv("TOKEN")), []byte("synthetic-launcher-selection")) || os.Getenv("OTHER") != "" || os.Getenv("X") != "" {
		fail()
	}
	self, err := os.Executable()
	if err != nil {
		fail()
	}
	child := exec.Command(self, "launcher-child", "descendant", dir)
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if child.Start() != nil || writeLauncherPID(filepath.Join(dir, "child.pid"), os.Getpid()) != nil {
		fail()
	}
	if mode == "blocked" || mode == "broken" {
		// Let the descendant initialize its shared standard handles before a
		// synchronous pipe write blocks operations on the same file object.
		handle, err := launcherPID(filepath.Join(dir, "descendant.pid"))
		if err != nil {
			fail()
		}
		windows.CloseHandle(handle)
		if os.WriteFile(filepath.Join(dir, "output-started"), []byte("ready"), 0600) != nil {
			fail()
		}
		chunk := bytes.Repeat([]byte{'x'}, 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				// A child may ignore output errors under direct inheritance.
				_ = os.WriteFile(filepath.Join(dir, "output-error"), []byte("observed"), 0600)
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
	_, _ = os.Stderr.Write([]byte("separate-stderr"))
	_, _ = io.Copy(os.Stdout, os.Stdin)
	if mode == "protocol" {
		windows.ExitProcess(0xf1234567)
	}
	if mode != "ignore" {
		fail()
	}
	for {
		time.Sleep(time.Second)
	}
}

// launcherHost is deliberately not a kill-on-close Job owner. Killing it alone
// must not be mistaken for killing the wrapper that owns the containment Job.
func launcherHost(args []string) {
	if len(args) < 3 || !filepath.IsAbs(args[0]) || !filepath.IsAbs(args[1]) {
		fail()
	}
	child := exec.Command(args[0], args[2:]...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if child.Start() != nil || writeLauncherPID(filepath.Join(args[1], "wrapper.pid"), child.Process.Pid) != nil {
		fail()
	}
	_ = child.Wait()
	os.Exit(0)
}

func launcherPID(path string) (windows.Handle, error) {
	failure := errors.New("synthetic launcher readiness failed")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(path)
		pid, err := strconv.ParseUint(string(data), 10, 32)
		if err == nil && pid != 0 {
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
			if err != nil {
				return 0, failure
			}
			return handle, nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, failure
}

func launcherWait(handle windows.Handle, timeout uint32, want uint32) bool {
	status, err := windows.WaitForSingleObject(handle, timeout)
	return err == nil && status == want
}

func launcherLifecycle(req request) (result, error) {
	failure := errors.New("synthetic launcher lifecycle failed")
	if !filepath.IsAbs(req.Executable) || !filepath.IsAbs(req.Path) || len(req.Value) != 0 || req.Reference != "" || len(req.Args) != 0 {
		return result{}, failure
	}
	root, err := os.OpenRoot(req.Path)
	if err != nil {
		return result{}, failure
	}
	defer root.Close()
	self, err := os.Executable()
	if err != nil {
		return result{}, failure
	}
	for _, mode := range []string{"protocol", "ignore", "blocked", "broken", "host death"} {
		if secure.CreatePrivateDirectory(root, mode) != nil {
			return result{}, failure
		}
		dir, err := secure.OpenPrivateDirectory(root, mode)
		if err != nil {
			return result{}, failure
		}
		err = launcherScenario(req.Executable, self, filepath.Join(req.Path, mode), dir, mode)
		dir.Close()
		if err != nil {
			return result{}, fmt.Errorf("synthetic launcher %s: %w", mode, err)
		}
	}
	return result{Code: 0}, nil
}

func launcherScenario(image, self, path string, dir *os.Root, mode string) error {
	failure := errors.New("synthetic launcher lifecycle failed")
	file, err := secure.CreatePrivateFile(dir, "synthetic.store")
	if err != nil {
		return failure
	}
	data := []byte("TOKEN=synthetic-launcher-selection\nOTHER=synthetic-unselected\n")
	_, err = file.Write(data)
	secure.Clear(data)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return failure
	}
	input, inputWrite, err := os.Pipe()
	if err != nil {
		return failure
	}
	defer input.Close()
	defer inputWrite.Close()
	output, outputWrite, err := os.Pipe()
	if err != nil {
		return failure
	}
	defer output.Close()
	defer outputWrite.Close()
	diagnostic, err := secure.CreatePrivateFile(dir, "stderr")
	if err != nil {
		return failure
	}
	defer diagnostic.Close()
	childMode := mode
	if mode == "host death" {
		childMode = "ignore"
	}
	args := []string{"exec", "-f", "file:" + filepath.Join(path, "synthetic.store"), "--key", "TOKEN", "--optional-key", "X", "--", self, "launcher-child", childMode, path}
	cmd := exec.Command(image, args...)
	if mode == "host death" {
		cmd = exec.Command(self, append([]string{"launcher-host", image, path}, args...)...)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, outputWrite, diagnostic
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	// Selection must remove ambient registered and absent optional keys.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "TOKEN") && !strings.EqualFold(key, "OTHER") && !strings.EqualFold(key, "X") &&
			!strings.EqualFold(key, "HOME") && !strings.EqualFold(key, "USERPROFILE") && !strings.EqualFold(key, "SECRETS_DIR") && !strings.EqualFold(key, "SECRETS_ENV") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "TOKEN=ambient", "OTHER=ambient", "X=ambient", "HOME="+path, "USERPROFILE="+path, "SECRETS_DIR="+path, "SECRETS_ENV="+filepath.Join(path, "absent.env"))
	if cmd.Start() != nil {
		return failure
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	input.Close()
	outputWrite.Close()
	parent, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		return failure
	}
	defer windows.CloseHandle(parent)
	wrapper := parent
	if mode == "host death" {
		wrapper, err = launcherPID(filepath.Join(path, "wrapper.pid"))
		if err != nil {
			return failure
		}
		defer windows.CloseHandle(wrapper)
	}
	// Pin every live identity before releasing EOF or initiating any termination.
	defer windows.TerminateProcess(wrapper, 1)
	child, err := launcherPID(filepath.Join(path, "child.pid"))
	if err != nil {
		return errors.New("child readiness failed")
	}
	defer windows.CloseHandle(child)
	defer windows.TerminateProcess(child, 1)
	descendant, err := launcherPID(filepath.Join(path, "descendant.pid"))
	if err != nil {
		return errors.New("descendant readiness failed")
	}
	defer windows.CloseHandle(descendant)
	defer windows.TerminateProcess(descendant, 1)
	if mode == "protocol" {
		exchange := func(message []byte) bool {
			done := make(chan bool, 1)
			go func() {
				_, err := inputWrite.Write(message)
				got := make([]byte, len(message))
				_, readErr := io.ReadFull(output, got)
				done <- err == nil && readErr == nil && bytes.Equal(got, message)
			}()
			select {
			case ok := <-done:
				return ok
			case <-time.After(5 * time.Second):
				return false
			}
		}
		if !exchange([]byte("before\x00\xff\n")) {
			return errors.New("initial protocol exchange failed")
		}
		if !launcherWait(wrapper, 20000, uint32(windows.WAIT_TIMEOUT)) {
			return errors.New("unlimited lifetime failed")
		}
		if !exchange([]byte("after\x00\xfe\n")) {
			return errors.New("post-idle protocol exchange failed")
		}
		inputWrite.Close()
		if !launcherWait(wrapper, 5000, windows.WAIT_OBJECT_0) {
			return failure
		}
		var code uint32
		if windows.GetExitCodeProcess(wrapper, &code) != nil || code != 0xf1234567 {
			return errors.New("full-width status failed")
		}
		remaining, err := io.ReadAll(output)
		stderr, readErr := os.ReadFile(filepath.Join(path, "stderr"))
		if err != nil || len(remaining) != 0 || readErr != nil || string(stderr) != "separate-stderr" {
			return fmt.Errorf("separate stream verification failed (read=%t, extra=%t, stderr-read=%t, stderr=%t)", err != nil, len(remaining) != 0, readErr != nil, string(stderr) != "separate-stderr")
		}
	} else {
		inputWrite.Close()
		if mode == "broken" {
			output.Close()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(path, "output-error")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					return failure
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		if mode == "host death" {
			if windows.TerminateProcess(parent, 1) != nil || !launcherWait(parent, 5000, windows.WAIT_OBJECT_0) {
				return failure
			}
		}
		if !launcherWait(wrapper, 3000, uint32(windows.WAIT_TIMEOUT)) || !launcherWait(child, 0, uint32(windows.WAIT_TIMEOUT)) || !launcherWait(descendant, 0, uint32(windows.WAIT_TIMEOUT)) {
			return errors.New("direct child lifetime failed")
		}
		if windows.TerminateProcess(wrapper, 1) != nil || !launcherWait(wrapper, 5000, windows.WAIT_OBJECT_0) {
			return errors.New("forced wrapper termination failed")
		}
	}
	for _, handle := range []windows.Handle{child, descendant} {
		if !launcherWait(handle, 5000, windows.WAIT_OBJECT_0) {
			return errors.New("pinned descendant termination failed")
		}
	}
	return nil
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
