//go:build windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
	"github.com/avhn/secret/internal/transport"
	"golang.org/x/sys/windows"
)

func TestWindowsTemplateCloseFailureCleanup(t *testing.T) {
	home := syntheticTemplateHome(t)
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", home)
	storePath := filepath.Join(home, "synthetic.store")
	templatePath := filepath.Join(home, "synthetic.tmpl")
	if testutil.WriteFile(storePath, []byte("TOKEN=synthetic-template-value\n"), 0600) != nil || testutil.WriteFile(templatePath, []byte("{{TOKEN}}"), 0600) != nil {
		t.Fatal("cannot write synthetic fixtures")
	}

	originalClose := closeWindowsProcess
	t.Cleanup(func() { closeWindowsProcess = originalClose })
	var closeErr error
	var payloadPath string
	var payloadPresentAtClose bool
	closeCalls := 0
	closeWindowsProcess = func(process *transport.WindowsProcess) error {
		closeCalls++
		// Release the real native resources even though the reported result fails.
		closeErr = originalClose(process)
		paths, err := filepath.Glob(filepath.Join(home, ".secrets", ".rendered", "*", "payload"))
		if err == nil && len(paths) == 1 {
			payloadPath = paths[0]
			info, err := os.Lstat(payloadPath)
			payloadPresentAtClose = err == nil && info.Mode().IsRegular()
		}
		return errors.New("synthetic close failure")
	}

	var out, diagnostic bytes.Buffer
	args := []string{"run", "-f", "file:" + storePath, "--template-file", templatePath, "--"}
	status := Main(append(args, windowsCLIArgs("mark", home)...), os.Stdin, &out, &diagnostic)
	if status == 0 || diagnostic.String() != "secret: child supervision failed\n" || out.Len() != 0 {
		t.Fatal("Close failure did not produce only the fixed supervision diagnostic")
	}
	if closeCalls != 1 || closeErr != nil {
		t.Fatal("injected Close did not release native resources exactly once")
	}
	if _, err := os.Stat(filepath.Join(home, "started")); err != nil {
		t.Fatal("synthetic child did not run")
	}
	if !payloadPresentAtClose {
		t.Fatal("payload removal preceded injected Close")
	}
	for _, path := range []string{payloadPath, filepath.Dir(payloadPath)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("private template survived Close failure")
		}
	}
}

func TestWindowsTemplateJobCleanup(t *testing.T) {
	for _, failOutput := range []bool{false, true} {
		t.Run(strconv.FormatBool(failOutput), func(t *testing.T) {
			home := testutil.TempDir(t)
			t.Setenv("HOME", home)
			t.Setenv("SECRETS_DIR", home)
			store := filepath.Join(home, "synthetic.store")
			template := filepath.Join(home, "synthetic.tmpl")
			if testutil.WriteFile(store, []byte("TOKEN=synthetic-template-value\n"), 0600) != nil || testutil.WriteFile(template, []byte("{{TOKEN}}"), 0600) != nil {
				t.Fatal("cannot write synthetic fixtures")
			}
			var out, diagnostic bytes.Buffer
			c := command{in: os.Stdin, out: &out, errOut: &diagnostic}
			if failOutput {
				c.out = failingWriter{}
			}
			args := []string{"run", "-f", "file:" + store, "--template-file", template, "--", os.Args[0], "-test.run=^TestWindowsTemplateChild$", "--", home, "parent"}
			finished := make(chan int, 1)
			go func() { finished <- Main(args, c.in, c.out, c.errOut) }()
			pidPath := filepath.Join(home, "template-descendant.pid")
			deadline := time.Now().Add(10 * time.Second)
			var pidBytes []byte
			var err error
			for {
				pidBytes, err = os.ReadFile(pidPath)
				if err == nil && len(pidBytes) != 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("template descendant did not start")
				}
				time.Sleep(10 * time.Millisecond)
			}
			pid, err := strconv.Atoi(string(pidBytes))
			if err != nil {
				t.Fatal(err)
			}
			// Keep the live process identity pinned before allowing its parent
			// to exit. Reopening a PID after cleanup can observe a reused PID.
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
			if err != nil {
				t.Fatal("cannot observe template descendant")
			}
			t.Cleanup(func() { windows.TerminateProcess(handle, 1); windows.CloseHandle(handle) })
			if err := os.WriteFile(filepath.Join(home, "release"), []byte("ready"), 0600); err != nil {
				t.Fatal(err)
			}
			var status int
			select {
			case status = <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("template supervisor exceeded cleanup bound")
			}
			if failOutput {
				if status == 0 {
					t.Fatal("output failure accepted")
				}
			} else if status != 0 || out.String() != "<redacted>" {
				t.Fatal("private template output not redacted")
			}
			data, err := os.ReadFile(filepath.Join(home, "rendered.path"))
			if err != nil {
				t.Fatal("template child did not run")
			}
			if _, err := os.Stat(string(data)); !os.IsNotExist(err) {
				t.Fatal("private template survived supervisor return")
			}
			if status, err := windows.WaitForSingleObject(handle, 0); err != nil || status != windows.WAIT_OBJECT_0 {
				t.Fatal("template cleanup preceded Job containment completion")
			}
		})
	}
}

func TestWindowsTemplateChild(t *testing.T) {
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
	dir, mode := os.Args[index+1], os.Args[index+2]
	if mode == "descendant" {
		if os.WriteFile(filepath.Join(dir, "template-descendant.pid"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
			os.Exit(2)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	path := os.Getenv("SECRET_TEMPLATE_FILE")
	value, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(value, []byte("synthetic-template-value")) {
		os.Exit(2)
	}
	defer secure.Clear(value)
	if os.WriteFile(filepath.Join(dir, "rendered.path"), []byte(path), 0600) != nil {
		os.Exit(2)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestWindowsTemplateChild$", "--", dir, "descendant")
	if child.Start() != nil {
		os.Exit(2)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "template-descendant.pid")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(2)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			os.Exit(2)
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Stdout.Write(value)
	secure.Clear(value)
	os.Exit(0)
}
