//go:build windows

package transport

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrWindowsProcess = errors.New("Windows child supervision failed")

// PROC_THREAD_ATTRIBUTE_JOB_LIST is ProcThreadAttributeValue(13, false, true, false).
// x/sys does not currently declare this Windows 10 process-creation attribute.
const procThreadAttributeJobList = 0x0002000d

// WindowsExecutable resolves using only the constructed child PATH/PATHEXT.
// There is no implicit shell, application-directory, system-directory or cwd
// search. Relative PATH entries are skipped; explicit relative image paths work.
// Only .exe/.com images are accepted; .bat/.cmd require an explicit shell command.
func WindowsExecutable(name string, env []string) (string, error) {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\"") {
		return "", ErrWindowsProcess
	}
	path, extensions := "", ".COM;.EXE"
	for _, entry := range env {
		key, ok := WindowsEnvironmentKey(entry)
		if !ok {
			return "", ErrWindowsEnvironment
		}
		switch strings.ToUpper(key) {
		case "PATH":
			path = entry[len(key)+1:]
		case "PATHEXT":
			extensions = entry[len(key)+1:]
		}
	}
	var suffixes []string
	if filepath.Ext(name) != "" {
		suffixes = []string{""}
	} else {
		for _, extension := range strings.Split(extensions, ";") {
			if strings.EqualFold(extension, ".EXE") || strings.EqualFold(extension, ".COM") {
				suffixes = append(suffixes, extension)
			}
		}
	}
	directories := filepath.SplitList(path)
	if strings.ContainsAny(name, `\/:`) {
		// Drive-relative and volume-less rooted names depend on hidden drive cwd
		// state. Reject those ambiguities rather than resolve against the parent.
		if filepath.VolumeName(name) != "" && !filepath.IsAbs(name) || strings.HasPrefix(name, `\`) && !filepath.IsAbs(name) || strings.HasPrefix(name, "/") && !filepath.IsAbs(name) {
			return "", ErrWindowsProcess
		}
		directories = []string{""}
	}
	for _, dir := range directories {
		if !strings.ContainsAny(name, `\/:`) && (!WindowsSearchDirectory(dir) || !filepath.IsAbs(dir)) {
			continue
		}
		for _, suffix := range suffixes {
			candidate := filepath.Join(dir, name+suffix)
			ext := filepath.Ext(candidate)
			if !strings.EqualFold(ext, ".EXE") && !strings.EqualFold(ext, ".COM") {
				continue
			}
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() {
				absolute, err := filepath.Abs(candidate)
				if err == nil {
					return absolute, nil
				}
			}
		}
	}
	return "", ErrWindowsProcess
}

// WindowsProcess owns a non-inheritable kill-on-close Job. Every process is
// enrolled by CreateProcess itself, never by AssignProcessToJobObject or a
// suspended-process fallback. Descendants cannot opt out through breakaway.
// Only duplicated stdio handles can be inherited, never the Job handle.
// Wait reports the full native uint32 exit code as int on supported Windows amd64.
// Close must complete before a caller removes any child-visible private payload.
type WindowsProcess struct {
	mu     sync.Mutex
	job    windows.Handle
	handle windows.Handle // Retain process identity until Job cleanup and forwarding finish.
	pid    uint32
	done   chan struct{}
	status int
	err    error
}

func StartWindowsProcess(args, env []string, stdin, stdout, stderr *os.File) (*WindowsProcess, error) {
	return startWindowsProcess(args, env, stdin, stdout, stderr, nil)
}

// boundary is a test-only observation seam, never a substitute for enrollment.
// It lets a separate synthetic parent be killed immediately before/after the
// native call, without adding environment-controlled pauses to production.
func startWindowsProcess(args, env []string, stdin, stdout, stderr *os.File, boundary func(string)) (*WindowsProcess, error) {
	block, err := WindowsEnvironment(env)
	if err != nil {
		return nil, err
	}
	defer clear(block)
	if len(args) == 0 {
		return nil, ErrWindowsProcess
	}
	for _, arg := range args {
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return nil, ErrWindowsProcess
		}
	}
	path, err := WindowsExecutable(args[0], env)
	if err != nil {
		return nil, err
	}
	application, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrWindowsProcess
	}
	commandLine, err := windows.UTF16FromString(windows.ComposeCommandLine(args))
	if err != nil {
		return nil, ErrWindowsProcess
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, ErrWindowsProcess
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, ErrWindowsProcess
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, ErrWindowsProcess
	}
	defer attributes.Delete()
	if err := attributes.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return nil, ErrWindowsProcess
	}
	files := []*os.File{stdin, stdout, stderr}
	handles := make([]windows.Handle, 0, 3)
	defer func() {
		for _, handle := range handles {
			windows.CloseHandle(handle)
		}
	}()
	for _, file := range files {
		if file == nil {
			return nil, ErrWindowsProcess
		}
		var handle windows.Handle
		err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()), windows.CurrentProcess(), &handle, 0, true, windows.DUPLICATE_SAME_ACCESS)
		runtime.KeepAlive(file)
		if err != nil {
			return nil, ErrWindowsProcess
		}
		handles = append(handles, handle)
	}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, ErrWindowsProcess
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = handles[0], handles[1], handles[2]
	startup.ProcThreadAttributeList = attributes.List()
	var info windows.ProcessInformation
	if boundary != nil {
		boundary("before creation")
	}
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP)
	err = windows.CreateProcess(application, &commandLine[0], nil, nil, true, flags, &block[0], nil, &startup.StartupInfo, &info)
	runtime.KeepAlive(handles)
	runtime.KeepAlive(job)
	if err != nil {
		// Includes incompatible enclosing Jobs: no retry outside containment.
		return nil, ErrWindowsProcess
	}
	if boundary != nil {
		boundary("after creation")
	}
	windows.CloseHandle(info.Thread)
	process := &WindowsProcess{job: job, handle: info.Process, pid: info.ProcessId, done: make(chan struct{})}
	ok = true
	go func() {
		defer close(process.done)
		result, err := windows.WaitForSingleObject(info.Process, windows.INFINITE)
		var code uint32
		if err != nil || result != windows.WAIT_OBJECT_0 || windows.GetExitCodeProcess(info.Process, &code) != nil {
			process.status, process.err = 1, ErrWindowsProcess
			return
		}
		process.status = int(code)
	}()
	return process, nil
}

func (process *WindowsProcess) Wait() (int, error) {
	<-process.done
	return process.status, process.err
}

func (process *WindowsProcess) Kill() {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.job != 0 {
		_ = windows.TerminateJobObject(process.job, 1)
	}
}

// CTRL_C cannot be scoped to CREATE_NEW_PROCESS_GROUP children. Forward console
// cancellation as CTRL_BREAK to that group, never broadcast to the parent's
// console. A supervisor escalates to Job termination after a bounded grace.
func (process *WindowsProcess) ForwardInterrupt() {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.job != 0 {
		_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, process.pid)
	}
}

func (process *WindowsProcess) Close() error {
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.job == 0 {
		return nil
	}
	defer func() {
		windows.CloseHandle(process.job)
		process.job = 0
		// Never close a handle underneath an outstanding native wait. A failed
		// shutdown still closes the kill-on-close Job immediately; the waiter
		// releases the process handle when the kernel confirms termination.
		select {
		case <-process.done:
			windows.CloseHandle(process.handle)
		default:
			go func() {
				<-process.done
				windows.CloseHandle(process.handle)
			}()
		}
	}()
	if windows.TerminateJobObject(process.job, 1) != nil {
		return ErrWindowsProcess
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		var accounting struct {
			Times                                                            [4]int64
			PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
		}
		err := windows.QueryInformationJobObject(process.job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
		if err != nil {
			return ErrWindowsProcess
		}
		if accounting.ActiveProcesses == 0 {
			select {
			case <-process.done:
				return nil
			case <-time.After(time.Until(deadline)):
				return ErrWindowsProcess
			}
		}
		if !time.Now().Before(deadline) {
			return ErrWindowsProcess
		}
		time.Sleep(10 * time.Millisecond)
	}
}
