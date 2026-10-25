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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"

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
		for _, execMode := range []bool{false, true} {
			dir := t.TempDir()
			var output, diagnostic bytes.Buffer
			c := command{in: os.Stdin, out: &output, errOut: &diagnostic}
			finished := make(chan int, 1)
			go func() {
				if execMode {
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
				if mode == "tree pipes" {
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

func TestWindowsRunConsoleCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := windowsCLIArgs("console supervisor", t.TempDir())
	parent := exec.CommandContext(ctx, args[0], args[1:]...)
	parent.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	if err := parent.Run(); err != nil {
		t.Fatal("Windows supervisor did not forward console cancellation")
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
	case "console supervisor":
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
		c := command{in: os.Stdin, out: io.Discard, errOut: io.Discard}
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
		if os.WriteFile(filepath.Join(dir, "descendant.pid"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(2)
		}
	default:
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}
