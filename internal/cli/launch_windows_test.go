//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
	"github.com/avhn/secret/internal/transport"
	"golang.org/x/sys/windows"
)

func windowsCLIArgs(mode, dir string) []string {
	return []string{os.Args[0], "-test.run=^TestWindowsCLIChild$", "--", mode, dir}
}

func TestWindowsEnvironmentSelection(t *testing.T) {
	selection := store.Selection{Keys: []string{"TOKEN", "OTHER"}, Matched: map[string]store.Record{"TOKEN": {Value: []byte("synthetic-selected")}}}
	env, err := childEnvironment([]string{"token=ambient", "other=ambient", "optional=ambient", "secret_child_data=ambient", "KEEP=synthetic", "=C:=C:\\synthetic"}, selection, nil, []string{"TOKEN", "OPTIONAL"}, "synthetic.store")
	if err != nil || strings.Join(env, "\n") != "KEEP=synthetic\n=C:=C:\\synthetic\nTOKEN=synthetic-selected" {
		t.Fatal("Windows names were not removed case-insensitively")
	}
	selection.Keys = []string{"TOKEN", "token"}
	if _, err := childEnvironment(nil, selection, nil, nil, "synthetic.store"); err != transport.ErrWindowsEnvironment {
		t.Fatal("case-colliding store keys were accepted")
	}
	selection.Keys = []string{"TOKEN"}
	if _, err := childEnvironment([]string{"keep=one", "KEEP=two"}, selection, nil, nil, "synthetic.store"); err != transport.ErrWindowsEnvironment {
		t.Fatal("case-colliding ambient keys were accepted")
	}
}

func TestWindowsLaunchFilteringAndExec(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.store")
	if err := testutil.WriteFile(path, []byte("TOKEN=synthetic-\u00e9-\U00010437\nOTHER=synthetic-unselected\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("SECRETS_DIR", dir)
	for _, mode := range []string{"run", "exec"} {
		var output, diagnostic bytes.Buffer
		args := []string{mode, "-f", "file:" + path, "--key", "TOKEN", "--"}
		status := Main(append(args, windowsCLIArgs("emit", dir)...), os.Stdin, &output, &diagnostic)
		want := "<redacted>/<redacted>"
		if mode == "exec" {
			want = "synthetic-\u00e9-\U00010437/synthetic-unselected"
		}
		if status != 37 || output.String() != want || diagnostic.String() != want {
			t.Fatal("Windows launch exit code or two-stream filtering changed")
		}
	}
}

func TestWindowsLaunchUTF16Filtering(t *testing.T) {
	dir := t.TempDir()
	var out, diagnostic bytes.Buffer
	c := command{in: os.Stdin, out: &out, errOut: &diagnostic}
	value := []byte("synthetic-é-𐐷")
	t.Setenv("TOKEN", string(value))
	env := os.Environ()
	if status := c.runChild(windowsCLIArgs("emit utf16", dir), env, [][]byte{value}); status != 0 || out.String() != "<redacted>" || diagnostic.String() != "<redacted>" {
		t.Fatal("native child UTF-16 output was not redacted on both streams")
	}
}

type windowsLaunchProvider struct{ owned []byte }

func (p *windowsLaunchProvider) Get(string, string) ([]byte, error) { return p.owned, nil }
func (*windowsLaunchProvider) Put(string, string, string, []byte) error {
	return errors.New("unexpected synthetic put")
}
func (*windowsLaunchProvider) Delete(string, string) error {
	return errors.New("unexpected synthetic delete")
}

func TestWindowsLaunchRejectsLossyFileAndWincredSources(t *testing.T) {
	for _, value := range [][]byte{{0xff}, {'x', 0, 'y'}} {
		for _, source := range []string{"file", "wincred"} {
			// The file grammar already excludes NUL assignments on every platform.
			if source == "file" && bytes.ContainsRune(value, 0) {
				continue
			}
			dir := testutil.TempDir(t)
			var output, diagnostic bytes.Buffer
			c := command{in: os.Stdin, out: &output, errOut: &diagnostic, dir: dir, loc: store.Locator{Home: dir, SecretsDir: dir}}
			ref := "file:" + filepath.Join(dir, "synthetic.store")
			var provider windowsLaunchProvider
			if source == "file" {
				data := append(append([]byte("TOKEN="), value...), '\n')
				if err := testutil.WriteFile(strings.TrimPrefix(ref, "file:"), data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				ref = "wincred:synthetic"
				path, _ := store.ManifestPath(dir, ref)
				if err := store.UpdateManifest(path, "wincred", "TOKEN", nil, "0123456789abcdef0123456789abcdef"); err != nil {
					t.Fatal(err)
				}
				provider.owned = bytes.Clone(value)
			}
			o := launchOptions{files: []string{ref}, args: windowsCLIArgs("mark", dir)}
			env, values, _, err := c.prepareLaunchWith(o, func(ref string) (backend.Provider, string, string, error) {
				return backend.DispatchWith(ref, &provider)
			})
			if err == nil {
				c.runChild(o.args, env, values)
			}
			if err != transport.ErrWindowsEnvironment {
				t.Fatal("lossy source was not rejected at the environment boundary")
			}
			if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
				t.Fatal("lossy source started a child")
			}
			for _, b := range provider.owned {
				if b != 0 {
					t.Fatal("failed preparation retained provider bytes")
				}
			}
			if output.Len() != 0 || diagnostic.Len() != 0 {
				t.Fatal("preparation emitted source bytes")
			}
		}
	}
}

func TestWindowsLaunchDescendantCleanup(t *testing.T) {
	for _, mode := range []string{"tree pipes", "tree closed"} {
		for _, launchMode := range []string{"run", "relay exec", "direct exec"} {
			dir := t.TempDir()
			var output, diagnostic bytes.Buffer
			c := command{in: os.Stdin, out: &output, errOut: &diagnostic}
			if launchMode == "direct exec" {
				out := windowsCLIFile(t, dir, "stdout")
				errOut := windowsCLIFile(t, dir, "stderr")
				c.out, c.errOut = out, errOut
			}
			finished := make(chan int, 1)
			go func() {
				if launchMode != "run" {
					finished <- c.execChild(windowsCLIArgs(mode, dir), os.Environ())
				} else {
					finished <- c.runChild(windowsCLIArgs(mode, dir), os.Environ(), nil)
				}
			}()
			pidPath := filepath.Join(dir, "descendant.pid")
			var pid uint64
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				data, _ := os.ReadFile(pidPath)
				pid, _ = strconv.ParseUint(string(data), 10, 32)
				if pid != 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if pid == 0 {
				t.Fatal("synthetic descendant did not start")
			}
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { windows.TerminateProcess(handle, 1); windows.CloseHandle(handle) })
			if err := os.WriteFile(filepath.Join(dir, "release"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case status := <-finished:
				want := 0
				if mode == "tree pipes" && launchMode != "direct exec" {
					want = 1
				}
				if status != want {
					t.Fatal("unexpected inherited-pipe supervision status")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Windows launch cleanup exceeded bound")
			}
			if result, err := windows.WaitForSingleObject(handle, 1000); err != nil || result != windows.WAIT_OBJECT_0 {
				t.Fatal("Windows launch left a grandchild alive")
			}
		}
	}
}

func windowsCLIFile(t *testing.T, dir, name string) *os.File {
	t.Helper()
	file, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func writeWindowsCLIPID(dir, name string, pid int) error {
	file, err := os.CreateTemp(dir, ".pid-*")
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
	return os.Rename(file.Name(), filepath.Join(dir, name))
}

func windowsCLIReady(t *testing.T, dir string) windows.Handle {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(filepath.Join(dir, "started"))
		pid, err := strconv.ParseUint(string(data), 10, 32)
		if err == nil && pid != 0 {
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { windows.TerminateProcess(handle, 1); windows.CloseHandle(handle) })
			return handle
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Windows child readiness timed out")
	return 0
}

func TestWindowsExecLongLivedEOF(t *testing.T) {
	for _, relay := range []bool{false, true} {
		t.Run(strconv.FormatBool(relay), func(t *testing.T) {
			dir := t.TempDir()
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer writer.Close()
			out, diagnostic := windowsCLIFile(t, dir, "stdout"), windowsCLIFile(t, dir, "stderr")
			c := command{in: input, out: out, errOut: diagnostic}
			if relay {
				c.errOut = io.MultiWriter(diagnostic) // Mixed file/non-file callers relay both.
			}
			finished := make(chan int, 1)
			go func() { finished <- c.execChild(windowsCLIArgs("eof aware", dir), os.Environ()) }()
			handle := windowsCLIReady(t, dir)
			before, after := []byte("before\x00\xff\n"), []byte("after\x00\xfe\n")
			if _, err := writer.Write(before); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				data, _ := os.ReadFile(out.Name())
				if bytes.Equal(data, before) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("pre-idle protocol bytes did not arrive")
				}
				time.Sleep(10 * time.Millisecond)
			}
			select {
			case <-finished:
				t.Fatal("exec ended during unlimited lifetime")
			case <-time.After(20 * time.Second):
			}
			if result, err := windows.WaitForSingleObject(handle, 0); err != nil || result != uint32(windows.WAIT_TIMEOUT) {
				t.Fatal("exec child did not remain alive beyond 15 seconds")
			}
			if _, err := writer.Write(after); err != nil {
				t.Fatal(err)
			}
			writer.Close()
			select {
			case status := <-finished:
				if status != 37 {
					t.Fatal("EOF exit status changed")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("EOF shutdown exceeded bound")
			}
			if result, err := windows.WaitForSingleObject(handle, 0); err != nil || result != windows.WAIT_OBJECT_0 {
				t.Fatal("EOF shutdown did not terminate child")
			}
			data, _ := os.ReadFile(out.Name())
			errors, _ := os.ReadFile(diagnostic.Name())
			if !bytes.Equal(data, append(before, after...)) || string(errors) != "separate-stderr" {
				t.Fatal("exec did not preserve exact separate stream bytes")
			}
			if _, err := out.Write(nil); err != nil {
				t.Fatal("exec closed caller-owned output")
			}
		})
	}
}

func TestWindowsExecDirectCancellation(t *testing.T) {
	for _, mode := range []string{"eof ignoring", "blocked output"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			defer writer.Close()
			output, outputWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			defer outputWrite.Close()
			c := command{in: input, out: outputWrite, errOut: windowsCLIFile(t, dir, "stderr")}
			signals, finished := make(chan os.Signal, 4), make(chan int, 1)
			go func() { finished <- c.windowsExecSignals(windowsCLIArgs(mode, dir), os.Environ(), signals) }()
			handle := windowsCLIReady(t, dir)
			writer.Close()
			if result, err := windows.WaitForSingleObject(handle, 2500); err != nil || result != uint32(windows.WAIT_TIMEOUT) {
				t.Fatal("direct exec imposed EOF or stalled-output supervision")
			}
			start := time.Now()
			signals <- os.Interrupt
			// Repeated signals must not restart the grace timer.
			time.Sleep(time.Second)
			signals <- syscall.SIGTERM
			select {
			case status := <-finished:
				if status != 130 || time.Since(start) < 2*time.Second || time.Since(start) > 4500*time.Millisecond {
					t.Fatal("direct exec changed first-signal status or extended grace")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("direct exec cancellation exceeded cleanup bound")
			}
			if result, err := windows.WaitForSingleObject(handle, 0); err != nil || result != windows.WAIT_OBJECT_0 {
				t.Fatal("direct exec returned before native child termination")
			}
		})
	}
}

func TestWindowsExecMixedWriters(t *testing.T) {
	for _, fileOut := range []bool{false, true} {
		dir := t.TempDir()
		file := windowsCLIFile(t, dir, "file")
		var buffer bytes.Buffer
		c := command{in: os.Stdin, out: &buffer, errOut: file}
		if fileOut {
			c.out, c.errOut = file, &buffer
		}
		if status := c.execChild(windowsCLIArgs("emit", dir), nil); status != 37 {
			t.Fatal("mixed-writer exec status changed")
		}
		data, _ := os.ReadFile(file.Name())
		if string(data) != "/synthetic-unselected" || !bytes.Equal(data, buffer.Bytes()) {
			t.Fatal("mixed-writer exec ignored a supplied writer")
		}
	}
}

func TestWindowsExecFailurePrecedence(t *testing.T) {
	for _, relay := range []bool{false, true} {
		for _, failure := range []string{"close", "close and cancellation", "wait and cancellation", "never wait", "never wait output"} {
			t.Run(strconv.FormatBool(relay)+"/"+failure, func(t *testing.T) {
				dir := t.TempDir()
				out, diagnostic := windowsCLIFile(t, dir, "stdout"), windowsCLIFile(t, dir, "stderr")
				c := command{in: os.Stdin, out: out, errOut: diagnostic}
				if relay {
					c.out = io.MultiWriter(out)
				}
				if failure == "never wait output" {
					if !relay {
						t.Skip("direct output errors belong to the server")
					}
					c.out = failingWriter{}
				}
				originalWait, originalClose := waitWindowsProcess, closeWindowsProcess
				defer func() { waitWindowsProcess, closeWindowsProcess = originalWait, originalClose }()
				signals := make(chan os.Signal, 4)
				release, waiterDone := make(chan struct{}), make(chan struct{})
				var releaseOnce sync.Once
				processReady := make(chan *transport.WindowsProcess, 1)
				closed := false
				closeWindowsProcess = func(process *transport.WindowsProcess) error {
					closed = true
					err := originalClose(process)
					releaseOnce.Do(func() { close(release) })
					if strings.HasPrefix(failure, "close") {
						return errors.New("synthetic close error must not escape")
					}
					return err
				}
				waitWindowsProcess = func(process *transport.WindowsProcess) (int, error) {
					processReady <- process
					defer close(waiterDone)
					if failure == "close" {
						return originalWait(process)
					}
					if failure != "never wait output" {
						signals <- os.Interrupt
						for len(signals) > 0 {
							time.Sleep(time.Millisecond)
						}
					}
					if failure == "close and cancellation" {
						return originalWait(process)
					}
					if failure == "wait and cancellation" {
						process.Kill()
						_, _ = originalWait(process)
						return 0, errors.New("synthetic wait error must not escape")
					}
					<-release // No notification until checked Close has run.
					return originalWait(process)
				}
				mode := "mark"
				if failure != "close" {
					mode = "emit wait"
				}
				start := time.Now()
				finished := make(chan int, 1)
				go func() {
					finished <- c.windowsChildSignals(windowsCLIArgs(mode, dir), os.Environ(), nil, false, signals)
				}()
				var status int
				select {
				case status = <-finished:
				case <-time.After(7 * time.Second):
					// Release the injected waiter only for test cleanup on regression.
					select {
					case process := <-processReady:
						_ = originalClose(process)
					default:
					}
					releaseOnce.Do(func() { close(release) })
					select {
					case <-finished:
					case <-time.After(3 * time.Second):
					}
					t.Fatal("exec failed to reach checked Close without a wait notification")
				}
				<-waiterDone
				want := 1
				if failure == "never wait" {
					want = 130
				}
				if !closed || status != want || time.Since(start) > 8*time.Second {
					t.Fatal("exec did not reach checked Close with failure precedence within shutdown bound")
				}
				data, _ := os.ReadFile(diagnostic.Name())
				diagnosticText := "secret: child supervision failed\n"
				if failure == "never wait output" {
					diagnosticText = "secret: redaction filter failed\n"
				}
				if want == 1 && (!bytes.HasSuffix(data, []byte(diagnosticText)) || bytes.Count(data, []byte("secret: ")) != 1) || bytes.Contains(data, []byte("synthetic wait error")) || bytes.Contains(data, []byte("synthetic close error")) {
					t.Fatal("exec failure diagnostic missing or not fixed")
				}
			})
		}
	}
}

// A completed synthetic native result exercises WindowsProcess.Wait itself and
// its checked-Close recheck. Do not invalidate a handle under an active OS wait.
func failedWindowsProcess(t *testing.T) *transport.WindowsProcess {
	t.Helper()
	process := &transport.WindowsProcess{}
	done := make(chan struct{})
	close(done)
	state := reflect.ValueOf(process).Elem()
	for _, item := range []struct {
		name  string
		value any
	}{{"done", done}, {"status", 1}, {"err", transport.ErrWindowsProcess}} {
		field := state.FieldByName(item.name)
		if !field.IsValid() || !field.CanAddr() {
			t.Fatal("synthetic completed Windows process layout changed")
		}
		reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(item.value))
	}
	return process
}

func TestWindowsExecRealWaitFailureDiagnostic(t *testing.T) {
	for _, mode := range []string{"direct", "relay", "relay drain"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			out, diagnostic := windowsCLIFile(t, dir, "stdout"), windowsCLIFile(t, dir, "stderr")
			c := command{in: os.Stdin, out: out, errOut: diagnostic}
			if mode != "direct" {
				c.out = io.MultiWriter(out)
			}
			process := failedWindowsProcess(t)
			if _, err := process.Wait(); err != transport.ErrWindowsProcess {
				t.Fatal("real WindowsProcess.Wait did not return the failed native result")
			}
			originalStart := startWindowsProcess
			defer func() { startWindowsProcess = originalStart }()
			startWindowsProcess = func(_, _ []string, _, stdout, _ *os.File) (*transport.WindowsProcess, error) {
				if mode == "relay drain" {
					var handle windows.Handle
					if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(stdout.Fd()), windows.CurrentProcess(), &handle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
						t.Fatal(err)
					}
					hold := os.NewFile(uintptr(handle), "synthetic held stdout")
					t.Cleanup(func() { hold.Close() })
				}
				return process, nil
			}
			if status := c.execChild(windowsCLIArgs("mark", dir), os.Environ()); status != 1 {
				t.Fatal("real native wait failure did not retain failure status")
			}
			data, err := os.ReadFile(diagnostic.Name())
			want := "secret: child supervision failed\n"
			if mode == "relay drain" {
				want = "secret: redaction filter failed\n"
			}
			if err != nil || string(data) != want {
				t.Fatalf("native wait failure must emit exactly one fixed diagnostic, got %q", data)
			}
		})
	}
}

func TestWindowsExecLaunchFailureDiagnostics(t *testing.T) {
	for _, relay := range []bool{false, true} {
		for _, invalidEnvironment := range []bool{false, true} {
			t.Run(strconv.FormatBool(relay)+"/"+strconv.FormatBool(invalidEnvironment), func(t *testing.T) {
				dir := t.TempDir()
				out, diagnostic := windowsCLIFile(t, dir, "stdout"), windowsCLIFile(t, dir, "stderr")
				c := command{in: os.Stdin, out: out, errOut: diagnostic}
				if relay {
					c.out = io.MultiWriter(out)
				}
				args, env := []string{filepath.Join(dir, "missing.exe")}, os.Environ()
				want := "secret: Windows child supervision failed\n"
				if invalidEnvironment {
					args = windowsCLIArgs("mark", dir)
					env = append(env, "SYNTHETIC=\xff")
					want = "secret: invalid Windows child environment\n"
				}
				if status := c.execChild(args, env); status != 1 {
					t.Fatal("launch failure status changed")
				}
				data, err := os.ReadFile(diagnostic.Name())
				if err != nil || string(data) != want {
					t.Fatalf("direct and relay launch diagnostics differ: %q", data)
				}
				if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
					t.Fatal("launch failure started a child")
				}
			})
		}
	}
}

func TestWindowsExecFullStatusAndInvalidStreams(t *testing.T) {
	dir := t.TempDir()
	out, diagnostic := windowsCLIFile(t, dir, "stdout"), windowsCLIFile(t, dir, "stderr")
	c := command{in: os.Stdin, out: out, errOut: diagnostic}
	for _, writer := range []io.Writer{out, io.MultiWriter(out)} {
		c.out = writer
		if status := c.execChild(windowsCLIArgs("full status", dir), os.Environ()); uint32(status) != 0xf1234567 {
			t.Fatal("exec truncated native uint32 exit status")
		}
	}
	closed := windowsCLIFile(t, dir, "closed")
	closed.Close()
	invalid := os.NewFile(0, "synthetic invalid handle")
	if invalid != nil {
		defer invalid.Close()
	}
	for _, writer := range []io.Writer{(*os.File)(nil), closed, invalid} {
		for _, mixed := range []bool{false, true} {
			for _, invalidStderr := range []bool{false, true} {
				c.out, c.errOut = writer, diagnostic
				if mixed {
					c.errOut = io.Discard
				}
				if invalidStderr {
					c.out, c.errOut = c.errOut, writer
				}
				if c.execChild(windowsCLIArgs("mark", dir), os.Environ()) != 1 {
					t.Fatal("invalid output stream accepted")
				}
				if _, err := os.Stat(filepath.Join(dir, "started")); !os.IsNotExist(err) {
					t.Fatal("invalid output stream started child")
				}
			}
		}
	}
	c.out, c.errOut = out, diagnostic
	if c.execChild([]string{filepath.Join(dir, "missing.exe")}, os.Environ()) != 1 {
		t.Fatal("missing executable accepted")
	}
	signals := make(chan os.Signal, 1)
	signals <- os.Interrupt
	if c.windowsExecSignals(windowsCLIArgs("mark", dir), os.Environ(), signals) != 130 {
		t.Fatal("pre-start cancellation changed")
	}
}

func TestWindowsExecRelayOutputFailureAndStall(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	for _, writer := range []io.Writer{failingWriter{}, blockingWriter{blocked}} {
		var diagnostic bytes.Buffer
		c := command{in: os.Stdin, out: writer, errOut: &diagnostic}
		start := time.Now()
		if status := c.execChild(windowsCLIArgs("emit wait", t.TempDir()), os.Environ()); status != 1 || time.Since(start) > 5*time.Second {
			t.Fatal("relay exec output failure or stall was not bounded")
		}
	}
}

func TestWindowsRunOutputFailure(t *testing.T) {
	var diagnostic bytes.Buffer
	c := command{in: os.Stdin, out: failingWriter{}, errOut: &diagnostic}
	start := time.Now()
	if status := c.runChild(windowsCLIArgs("emit wait", t.TempDir()), os.Environ(), nil); status != 1 || time.Since(start) > 5*time.Second {
		t.Fatal("Windows output failure was not bounded")
	}
}

func TestWindowsRunBlockedOutput(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)
	var diagnostic bytes.Buffer
	c := command{in: os.Stdin, out: blockingWriter{blocked}, errOut: &diagnostic}
	start := time.Now()
	if status := c.runChild(windowsCLIArgs("emit wait", t.TempDir()), os.Environ(), nil); status != 1 || time.Since(start) > 5*time.Second {
		t.Fatal("Windows stalled output was not bounded")
	}
}

func TestWindowsRunDeadline(t *testing.T) {
	c := command{in: os.Stdin, out: io.Discard, errOut: io.Discard}
	start := time.Now()
	if status := c.runChild(windowsCLIArgs("emit wait", t.TempDir()), os.Environ(), nil); status != 1 || time.Since(start) < 15*time.Second || time.Since(start) > 22*time.Second {
		t.Fatal("Windows child runtime deadline was not enforced")
	}
}

func templateFailureChild(kind, dir string, _ []string) []string {
	if kind == "spawn" {
		return []string{filepath.Join(dir, "missing.exe")}
	}
	return windowsCLIArgs("template "+kind, dir)
}

func TestWindowsRunConsoleCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := windowsCLIArgs("console supervisor", t.TempDir())
	parent := exec.CommandContext(ctx, args[0], args[1:]...)
	parent.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	if err := parent.Run(); err != nil {
		t.Fatalf("Windows supervisor did not forward console cancellation: %v", err)
	}
}

func TestWindowsCLIChild(t *testing.T) {
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
	switch mode {
	case "full status":
		os.Exit(int(uint32(0xf1234567)))
	case "eof aware", "eof ignoring", "blocked output":
		if mode != "eof aware" {
			// A real console may be attached even when notifications are injected.
			// Ignore forwarded CTRL_BREAK so escalation, not default exit, is tested.
			signal.Notify(make(chan os.Signal, 4), os.Interrupt)
		}
		if writeWindowsCLIPID(dir, "started", os.Getpid()) != nil {
			os.Exit(2)
		}
		if mode == "blocked output" {
			chunk := bytes.Repeat([]byte{'x'}, 64<<10)
			for {
				// A direct child owns backpressure and may ignore a broken pipe.
				_, _ = os.Stdout.Write(chunk)
			}
		}
		_, _ = os.Stderr.Write([]byte("separate-stderr"))
		_, _ = io.Copy(os.Stdout, os.Stdin)
		if mode == "eof aware" {
			os.Exit(37)
		}
	case "console supervisor":
		// exec.Command fills STARTF_USESTDHANDLES with NUL/pipe handles on a
		// redirected runner. Own real console handles, and clear the inherited
		// CTRL_C-ignore attribute before testing the supervisor's signal path.
		console, err := openWindowsConsole()
		if err != nil {
			os.Exit(3)
		}
		defer console.Close()
		reset := windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")
		if ok, _, _ := reset.Call(0, 0); ok == 0 {
			os.Exit(3)
		}
		go func() {
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(dir, "console ready")); err == nil {
					// This test owns a separate console. The child group ignores
					// CTRL_C, so only the supervisor's scoped CTRL_BREAK reaches it.
					_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_C_EVENT, 0)
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		c := command{in: console.(*controllingConsole).input, out: io.Discard, errOut: io.Discard}
		status := c.runChild(windowsCLIArgs("console child", dir), os.Environ(), nil)
		if _, err := os.Stat(filepath.Join(dir, "console caught")); err != nil || status != 130 {
			os.Exit(2)
		}
		os.Exit(0)
	case "console child":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		if os.WriteFile(filepath.Join(dir, "console ready"), []byte("ready"), 0600) != nil {
			os.Exit(2)
		}
		select {
		case <-signals:
			if os.WriteFile(filepath.Join(dir, "console caught"), []byte("caught"), 0600) != nil {
				os.Exit(2)
			}
			os.Exit(42)
		case <-time.After(10 * time.Second):
			os.Exit(2)
		}
	case "template pipe drain":
		childArgs := windowsCLIArgs("descendant", dir)
		child := exec.Command(childArgs[0], childArgs[1:]...)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(2)
		}
		fallthrough
	case "template filter", "template missing placeholder", "template unselected key", "template exec", "template oversize", "template directory":
		value, err := os.ReadFile(os.Getenv("SECRET_TEMPLATE_FILE"))
		if err != nil {
			os.Exit(2)
		}
		os.Stdout.Write(value)
		clear(value)
		os.Exit(0)
	case "emit utf16":
		var value []byte
		for _, unit := range utf16.Encode([]rune(os.Getenv("TOKEN"))) {
			value = append(value, byte(unit), byte(unit>>8))
		}
		os.Stdout.Write(value)
		os.Stderr.Write(value)
		clear(value)
		os.Exit(0)
	case "emit", "emit wait":
		value := []byte(os.Getenv("TOKEN") + "/synthetic-unselected")
		os.Stdout.Write(value)
		os.Stderr.Write(value)
		if mode == "emit" {
			os.Exit(37)
		}
	case "mark":
		os.WriteFile(filepath.Join(dir, "started"), []byte("started"), 0600)
		os.Exit(0)
	case "tree pipes", "tree closed":
		args := windowsCLIArgs("descendant", dir)
		child := exec.Command(args[0], args[1:]...)
		if mode == "tree pipes" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if child.Start() != nil {
			os.Exit(2)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(2)
	case "descendant":
		if writeWindowsCLIPID(dir, "descendant.pid", os.Getpid()) != nil {
			os.Exit(2)
		}
	default:
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}
