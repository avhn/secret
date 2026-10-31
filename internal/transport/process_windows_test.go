//go:build windows

package transport

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsFixtureArgs(mode, dir string, extra ...string) []string {
	return append([]string{os.Args[0], "-test.run=^TestWindowsProcessFixture$", "--", mode, dir}, extra...)
}

func awaitWindowsFixture(t *testing.T, path string) []byte {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil && len(data) > 0 {
			return data
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("synthetic process readiness timed out")
	return nil
}

func fixtureProcessHandle(t *testing.T, path string) windows.Handle {
	t.Helper()
	pid, err := strconv.ParseUint(string(awaitWindowsFixture(t, path)), 10, 32)
	if err != nil {
		t.Fatal("invalid synthetic PID")
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		t.Fatal("cannot observe synthetic process")
	}
	t.Cleanup(func() { windows.TerminateProcess(handle, 1); windows.CloseHandle(handle) })
	return handle
}

func assertWindowsProcessStopped(t *testing.T, handle windows.Handle) {
	t.Helper()
	result, err := windows.WaitForSingleObject(handle, 5000)
	if err != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatal("synthetic descendant survived Job cleanup")
	}
}

func TestWindowsExecutableRejectsPlantedCWDImage(t *testing.T) {
	// Plant a real runnable image, not only an .exe-named placeholder.
	image, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "planted.exe"), image, 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	if _, err := WindowsExecutable("planted", []string{"PATH=.;relative;;", "PATHEXT=.EXE"}); err == nil {
		t.Fatal("planted cwd executable selected through relative PATH entries")
	}
	if got, err := WindowsExecutable(`.\planted.exe`, nil); err != nil || !strings.EqualFold(got, filepath.Join(dir, "planted.exe")) {
		t.Fatal("explicit relative executable path did not opt into cwd resolution")
	}
}

func TestWindowsExecutableChildSearch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // Must not supply a fallback for an empty child PATH.
	t.Chdir(dir)
	for _, name := range []string{"synthetic.exe", "synthetic.com", "script.cmd"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir("planted", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("planted", "synthetic.exe"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, ext, want string
	}{
		{"synthetic", dir, ".EXE;.COM", "synthetic.EXE"},
		{"synthetic", dir, ".COM;.EXE", "synthetic.COM"},
		{"synthetic.exe", dir, ".COM", "synthetic.exe"},
		{"synthetic", dir, ".CMD;.EXE", "synthetic.EXE"},
		{"script", dir, ".CMD", ""},
		{"script.cmd", dir, ".CMD", ""},
		{"synthetic", "", ".EXE", ""},
		{"synthetic", ".", ".EXE", ""},
		{"synthetic", ";", ".EXE", ""},
		{"synthetic", "planted", ".EXE", ""},
		{"synthetic", ".;planted;" + dir, ".EXE", "synthetic.EXE"},
		{`.\synthetic.exe`, "", ".EXE", "synthetic.exe"},
		{"synthetic", dir, "", ""},
		{`C:synthetic.exe`, dir, ".EXE", ""},
		{`\synthetic.exe`, dir, ".EXE", ""},
		{filepath.Join(dir, "synthetic"), "", ".EXE", "synthetic.EXE"},
	} {
		got, err := WindowsExecutable(test.name, []string{"Path=" + test.path, "PathExt=" + test.ext})
		if test.want == "" {
			if err == nil {
				t.Fatal("unsupported executable resolved")
			}
		} else if err != nil || !strings.EqualFold(got, filepath.Join(dir, test.want)) {
			t.Fatal("executable did not use child PATH/PATHEXT")
		}
	}
}

func TestWindowsProcessEnvironmentExitAndQuoting(t *testing.T) {
	for _, code := range []uint32{0, 23, 259, 0xf1234567} {
		dir := t.TempDir()
		output, err := os.Create(filepath.Join(dir, "stdout"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { output.Close() })
		env := append(os.Environ(), "SECRET_SYNTHETIC_ROUNDTRIP=synthetic-é-\U00010437=a")
		args := windowsFixtureArgs("roundtrip", dir, strconv.FormatUint(uint64(code), 10), "", `space quote" slash\`)
		process, err := StartWindowsProcess(args, env, os.Stdin, output, output)
		if err != nil {
			t.Fatal(err)
		}
		got, err := process.Wait()
		if err != nil || got != int(code) {
			t.Fatal("native exit code was not preserved")
		}
		if err := process.Close(); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(dir, "stdout"))
		if err != nil || !bytes.Equal(data, []byte("synthetic-é-\U00010437=a")) {
			t.Fatal("native environment or argv did not round trip")
		}
	}
}

func TestWindowsProcessRejectsEnvironmentBeforeCreation(t *testing.T) {
	for _, entry := range []string{"SYNTHETIC=\xff", "SYNTHETIC=\x00", "\xff=synthetic", "=BAD=synthetic"} {
		dir := t.TempDir()
		process, err := StartWindowsProcess(windowsFixtureArgs("mark", dir), append(os.Environ(), entry), os.Stdin, os.Stdout, os.Stderr)
		if process != nil || err != ErrWindowsEnvironment {
			if process != nil {
				process.Close()
			}
			t.Fatal("lossy environment was not rejected before creation")
		}
		if _, err := os.Stat(filepath.Join(dir, "child.pid")); !os.IsNotExist(err) {
			t.Fatal("child started for an invalid environment")
		}
	}
}

func TestWindowsProcessJobContainmentAndHandleList(t *testing.T) {
	dir := t.TempDir()
	// Deliberately inheritable unrelated handle. It must not reach the child.
	event, err := windows.CreateEvent(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(event)
	process, err := StartWindowsProcess(windowsFixtureArgs("tree", dir, strconv.FormatUint(uint64(event), 10)), os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { process.Close() })
	child := fixtureProcessHandle(t, filepath.Join(dir, "child.pid"))
	grandchild := fixtureProcessHandle(t, filepath.Join(dir, "grandchild.pid"))
	awaitWindowsFixture(t, filepath.Join(dir, "ready"))
	if result, _ := windows.WaitForSingleObject(event, 0); result != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("unrelated inheritable handle reached the child")
	}
	var members struct {
		Assigned, Count uint32
		PIDs            [8]uintptr
	}
	if err := windows.QueryInformationJobObject(process.job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&members)), uint32(unsafe.Sizeof(members)), nil); err != nil || members.Count != 2 {
		t.Fatal("direct child and grandchild were not enrolled in the same Job")
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	for _, handle := range []windows.Handle{child, grandchild} {
		if result, err := windows.WaitForSingleObject(handle, 0); err != nil || result != windows.WAIT_OBJECT_0 {
			t.Fatal("Close returned before every Job member was signaled")
		}
	}
}

func TestWindowsProcessKillRetainsDescendants(t *testing.T) {
	dir := t.TempDir()
	process, err := StartWindowsProcess(windowsFixtureArgs("tree", dir), os.Environ(), os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { process.Close() })
	grandchild := fixtureProcessHandle(t, filepath.Join(dir, "grandchild.pid"))
	awaitWindowsFixture(t, filepath.Join(dir, "ready"))
	process.Kill()
	// The supervisor may call Kill well before Close. Reopening a PID after
	// termination is not a substitute for retaining the live member identity.
	if len(process.members) != 1 || process.memberErr != nil {
		t.Fatal("Kill did not retain the descendant before termination")
	}
	if err := process.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := windows.WaitForSingleObject(grandchild, 0); err != nil || result != windows.WAIT_OBJECT_0 {
		t.Fatal("Close returned before the previously killed descendant was signaled")
	}
}

func TestWindowsProcessParentDeathAtCreationBoundary(t *testing.T) {
	for _, boundary := range []string{"before creation", "after creation"} {
		t.Run(boundary, func(t *testing.T) {
			dir := t.TempDir()
			args := windowsFixtureArgs("parent", dir, boundary)
			parent := exec.Command(args[0], args[1:]...)
			if err := parent.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { parent.Process.Kill() })
			awaitWindowsFixture(t, filepath.Join(dir, "boundary"))
			var descendants []windows.Handle
			if boundary == "after creation" {
				descendants = append(descendants, fixtureProcessHandle(t, filepath.Join(dir, "child.pid")), fixtureProcessHandle(t, filepath.Join(dir, "grandchild.pid")))
			}
			if err := parent.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = parent.Wait()
			for _, handle := range descendants {
				assertWindowsProcessStopped(t, handle)
			}
			if boundary == "before creation" {
				if _, err := os.Stat(filepath.Join(dir, "child.pid")); !os.IsNotExist(err) {
					t.Fatal("child existed before atomic creation")
				}
			}
		})
	}
}

func TestWindowsProcessIncompatibleEnclosingJob(t *testing.T) {
	dir := t.TempDir()
	args := windowsFixtureArgs("limited parent", dir)
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		// Exit 3 means the enclosing Job premise could not be established;
		// exit 2 means the launch was not refused with ErrWindowsProcess.
		t.Fatalf("incompatible enclosing Job fixture failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "child.pid")); !os.IsNotExist(err) {
		t.Fatal("incompatible Job launched a child outside containment")
	}
}

func TestWindowsProcessUIRestrictedEnclosingJob(t *testing.T) {
	args := windowsFixtureArgs("restricted parent", t.TempDir())
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		t.Fatalf("UI-restricted enclosing Job containment failed: %v", err)
	}
}

func TestWindowsProcessConsoleForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := windowsFixtureArgs("console parent", t.TempDir())
	parent := exec.CommandContext(ctx, args[0], args[1:]...)
	// Isolate console events from the CI runner and the test process itself.
	parent.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	if err := parent.Run(); err != nil {
		t.Fatal("scoped CTRL_BREAK forwarding failed")
	}
}

func TestWindowsProcessDetachedParentDeath(t *testing.T) {
	// Reuse the creation-boundary fixture with no console. Keep the existing
	// before/after enrollment, handle-list and incompatible-Job tests unchanged.
	dir := t.TempDir()
	args := windowsFixtureArgs("parent", dir, "after creation")
	parent := exec.Command(args[0], args[1:]...)
	parent.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { parent.Process.Kill(); parent.Wait() })
	awaitWindowsFixture(t, filepath.Join(dir, "boundary"))
	child := fixtureProcessHandle(t, filepath.Join(dir, "child.pid"))
	grandchild := fixtureProcessHandle(t, filepath.Join(dir, "grandchild.pid"))
	// Pin the still-live wrapper too, before initiating termination.
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(parent.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.TerminateProcess(handle, 1); err != nil {
		t.Fatal(err)
	}
	for _, process := range []windows.Handle{handle, child, grandchild} {
		assertWindowsProcessStopped(t, process)
	}
}

func TestWindowsProcessFixture(t *testing.T) {
	marker := -1
	for i, arg := range os.Args {
		if arg == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		return
	}
	args := os.Args[marker+1:]
	if len(args) < 2 {
		os.Exit(2)
	}
	mode, dir := args[0], args[1]
	write := func(name, data string) {
		// Readers must not pin an identity from a partially written PID.
		file, err := os.CreateTemp(dir, ".ready-*")
		if err != nil {
			os.Exit(2)
		}
		_, err = file.WriteString(data)
		closeErr := file.Close()
		if err != nil || closeErr != nil || os.Rename(file.Name(), filepath.Join(dir, name)) != nil {
			os.Remove(file.Name())
			os.Exit(2)
		}
	}
	waitFile := func(name string) {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil && len(data) > 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		os.Exit(2)
	}
	switch mode {
	case "console child":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		write("console ready", "ready")
		select {
		case <-signals:
			os.Exit(42)
		case <-time.After(10 * time.Second):
			os.Exit(2)
		}
	case "console parent":
		process, err := StartWindowsProcess(windowsFixtureArgs("console child", dir), os.Environ(), os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			os.Exit(2)
		}
		waitFile("console ready")
		process.ForwardInterrupt()
		code, err := process.Wait()
		closeErr := process.Close()
		if err != nil || closeErr != nil || code != 42 {
			os.Exit(2)
		}
		os.Exit(0)
	case "roundtrip":
		if len(args) != 5 || args[3] != "" || args[4] != `space quote" slash\` {
			os.Exit(2)
		}
		os.Stdout.Write([]byte(os.Getenv("SECRET_SYNTHETIC_ROUNDTRIP")))
		code, _ := strconv.ParseUint(args[2], 10, 32)
		windows.ExitProcess(uint32(code))
	case "mark":
		write("child.pid", strconv.Itoa(os.Getpid()))
		os.Exit(0)
	case "tree", "no breakaway tree":
		write("child.pid", strconv.Itoa(os.Getpid()))
		if mode == "no breakaway tree" {
			args := windowsFixtureArgs("mark", dir)
			escape := exec.Command(args[0], args[1:]...)
			escape.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_BREAKAWAY_FROM_JOB}
			if escape.Start() == nil {
				escape.Process.Kill()
				escape.Wait()
				os.Exit(4)
			}
		}
		if len(args) > 2 {
			handle, _ := strconv.ParseUint(args[2], 10, 64)
			_ = windows.SetEvent(windows.Handle(handle))
		}
		childArgs := windowsFixtureArgs("grandchild", dir)
		child := exec.Command(childArgs[0], childArgs[1:]...)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(2)
		}
		waitFile("grandchild.pid")
		write("ready", "ready")
	case "grandchild":
		write("grandchild.pid", strconv.Itoa(os.Getpid()))
	case "parent":
		process, err := startWindowsProcess(windowsFixtureArgs("tree", dir), os.Environ(), os.Stdin, os.Stdout, os.Stderr, func(stage string) {
			if stage == args[2] {
				if stage == "after creation" {
					waitFile("ready")
				}
				write("boundary", "ready")
				time.Sleep(30 * time.Second)
				os.Exit(2)
			}
		})
		if err != nil {
			os.Exit(2)
		}
		defer process.Close()
	case "restricted parent", "limited parent":
		job, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			os.Exit(3)
		}
		if mode == "restricted parent" {
			var limits windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
			limits.UIRestrictionsClass = windows.JOB_OBJECT_UILIMIT_HANDLES
			if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
				os.Exit(3)
			}
		} else {
			// The parent itself consumes the entire active-process allowance.
			// Unlike a UI restriction, this directly prevents admitting a child.
			var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
			limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
			limits.BasicLimitInformation.ActiveProcessLimit = 1
			if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
				os.Exit(3)
			}
		}
		if windows.AssignProcessToJobObject(job, windows.CurrentProcess()) != nil {
			os.Exit(3)
		}
		childMode := "mark"
		if mode == "restricted parent" {
			childMode = "no breakaway tree"
		}
		process, err := StartWindowsProcess(windowsFixtureArgs(childMode, dir), os.Environ(), os.Stdin, os.Stdout, os.Stderr)
		if process == nil {
			if err != ErrWindowsProcess {
				os.Exit(2)
			}
			os.Exit(0)
		}
		if mode == "limited parent" || err != nil {
			process.Close()
			os.Exit(2)
		}
		// Successful JOB_LIST creation must not be mistaken for an escape.
		// Prove our exact Job owns both generations and retains all its limits.
		waitFile("ready")
		child := fixtureProcessHandle(t, filepath.Join(dir, "child.pid"))
		grandchild := fixtureProcessHandle(t, filepath.Join(dir, "grandchild.pid"))
		var members struct {
			Assigned, Count uint32
			PIDs            [8]uintptr
		}
		var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if windows.QueryInformationJobObject(process.job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&members)), uint32(unsafe.Sizeof(members)), nil) != nil || members.Count != 2 ||
			windows.QueryInformationJobObject(process.job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil) != nil || limits.BasicLimitInformation.LimitFlags != windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE {
			process.Close()
			os.Exit(2)
		}
		if windows.QueryInformationJobObject(job, windows.JobObjectBasicProcessIdList, uintptr(unsafe.Pointer(&members)), uint32(unsafe.Sizeof(members)), nil) != nil || members.Count != 3 {
			process.Close()
			os.Exit(2)
		}
		// Exercise the early Kill path as well as Close's own termination path.
		process.Kill()
		if process.Close() != nil {
			os.Exit(2)
		}
		for _, handle := range []windows.Handle{child, grandchild} {
			if result, err := windows.WaitForSingleObject(handle, 0); err != nil || result != windows.WAIT_OBJECT_0 {
				os.Exit(2)
			}
			windows.CloseHandle(handle)
		}
		os.Exit(0)
	default:
		os.Exit(2)
	}
	for {
		time.Sleep(time.Second)
	}
}
