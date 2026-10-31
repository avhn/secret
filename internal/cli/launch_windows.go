//go:build windows

package cli

import (
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/transport"
	"golang.org/x/sys/windows"
)

// Native process seams permit synthetic failures without changing native cleanup.
var startWindowsProcess = transport.StartWindowsProcess
var closeWindowsProcess = (*transport.WindowsProcess).Close
var waitWindowsProcess = (*transport.WindowsProcess).Wait

// One supervisory goroutine reports failures from wait, relay and checked Close.
// Keep the first fixed diagnostic, even when more than one stage fails.
func (c command) windowsExecFailure() func(string) int {
	reported := false
	return func(message string) int {
		if !reported {
			reported = true
			return c.runFailure(message)
		}
		return 1
	}
}

// Private rendering uses the native ACL primitives before child creation.
func launchTemplateUnsupported() bool { return false }

// Windows exec is a supervised, unfiltered child, not process replacement.
func (c command) execChild(args, env []string) int {
	return c.windowsChild(args, env, nil, false)
}

func (c command) runChild(args, env []string, values [][]byte) int {
	return c.windowsChild(args, env, values, true)
}

func (c command) runTemplateChild(args, env []string, values [][]byte, signals <-chan os.Signal) int {
	return c.windowsChildSignals(args, env, values, true, signals)
}

func (c command) windowsChild(args, env []string, values [][]byte, filtered bool) int {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	return c.windowsChildSignals(args, env, values, filtered, signals)
}

// windowsExecSignals owns direct stdio only when both supplied outputs are files.
// Mixed writers use the relay path, never global stdout/stderr substitutes.
func (c command) windowsExecSignals(args, env []string, signals <-chan os.Signal) (status int) {
	failure := c.windowsExecFailure()
	stdout, outFile := c.out.(*os.File)
	stderr, errFile := c.errOut.(*os.File)
	// Reject typed-nil and closed files even in mixed-writer calls, before spawn.
	if c.in == nil || outFile && stdout == nil || errFile && stderr == nil {
		return failure("child launch failed")
	}
	for _, file := range []*os.File{c.in, stdout, stderr} {
		if file != nil {
			if _, err := windows.GetFileType(windows.Handle(file.Fd())); err != nil {
				return failure("child launch failed")
			}
		}
	}
	if !outFile || !errFile {
		return c.windowsRelaySignals(args, env, nil, false, signals)
	}
	select {
	case s := <-signals:
		return 128 + int(s.(syscall.Signal))
	default:
	}
	process, err := startWindowsProcess(args, env, c.in, stdout, stderr)
	if err != nil {
		return failure(err.Error())
	}
	defer func() { status = c.closeWindowsExec(process, status, failure) }()
	return c.waitWindowsExec(process, signals, failure)
}

func (c command) closeWindowsExec(process *transport.WindowsProcess, status int, failure func(string) int) int {
	if closeWindowsProcess(process) != nil {
		return failure("child supervision failed")
	}
	// Successful Close has already confirmed the native wait. Read its result
	// without depending on the supervisor goroutine to send another notification.
	if _, err := process.Wait(); err != nil {
		return failure("child supervision failed")
	}
	return status
}

// waitWindowsExec waits for the direct child, not EOF or descendant lifetime.
// On cancellation escalation, checked Close must not depend on a wait notification.
func (c command) waitWindowsExec(process *transport.WindowsProcess, signals <-chan os.Signal, failure func(string) int) int {
	type result struct {
		code int
		err  error
	}
	waited := make(chan result, 1)
	go func() {
		code, err := waitWindowsProcess(process)
		waited <- result{code, err}
	}()
	var grace <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	interrupted := 0
	for {
		select {
		case s := <-signals:
			process.ForwardInterrupt()
			if interrupted == 0 {
				interrupted = 128 + int(s.(syscall.Signal))
				timer = time.NewTimer(2 * time.Second)
				grace = timer.C
			}
		case got := <-waited:
			if got.err != nil {
				return failure("child supervision failed")
			}
			if interrupted != 0 {
				return interrupted
			}
			return got.code
		case <-grace:
			process.Kill()
			select {
			case got := <-waited:
				if got.err != nil {
					return failure("child supervision failed")
				}
			default:
			}
			return interrupted
		}
	}
}

func (c command) windowsChildSignals(args, env []string, values [][]byte, filtered bool, signals <-chan os.Signal) int {
	if !filtered {
		return c.windowsExecSignals(args, env, signals)
	}
	return c.windowsRelaySignals(args, env, values, true, signals)
}

func (c command) windowsRelaySignals(args, env []string, values [][]byte, filtered bool, signals <-chan os.Signal) (status int) {
	failure := c.runFailure
	if !filtered {
		failure = c.windowsExecFailure()
	}
	copyStream := func(r io.Reader, w io.Writer) error {
		_, err := io.Copy(w, r)
		return err
	}
	if filtered {
		matcher, err := transport.NewWindowsMatcher(values)
		if err != nil {
			return failure(err.Error())
		}
		copyStream = matcher.Filter
	}
	stdout, outWrite, err := os.Pipe()
	if err != nil {
		return failure("child launch failed")
	}
	defer stdout.Close()
	defer outWrite.Close()
	stderr, errWrite, err := os.Pipe()
	if err != nil {
		return failure("child launch failed")
	}
	defer stderr.Close()
	defer errWrite.Close()
	select {
	case s := <-signals:
		return 128 + int(s.(syscall.Signal))
	default:
	}
	process, err := startWindowsProcess(args, env, c.in, outWrite, errWrite)
	if err != nil {
		return failure(err.Error())
	}
	outWrite.Close()
	errWrite.Close()
	defer func() {
		if !filtered {
			status = c.closeWindowsExec(process, status, failure)
		} else if closeWindowsProcess(process) != nil {
			status = c.runFailure("child supervision failed")
		}
	}()
	waitErrors := make(chan error, 1)
	child := supervisedProcess{
		wait: func() int {
			code, err := waitWindowsProcess(process)
			waitErrors <- err
			if err != nil {
				return 1
			}
			return code
		},
		kill:    process.Kill,
		forward: func(os.Signal) { process.ForwardInterrupt() },
	}
	maxRun := 15 * time.Second
	if !filtered {
		maxRun = 0
		child.shutdownWait = 2 * time.Second
		child.failure = failure
	}
	status = c.superviseChild(child, stdout, stderr, copyStream, signals, maxRun, 250*time.Millisecond)
	if !filtered {
		// A native wait failure takes precedence over an observed cancellation.
		// The channel also avoids racing a waiter after bounded shutdown returns.
		select {
		case err := <-waitErrors:
			if err != nil {
				return failure("child supervision failed")
			}
		default:
		}
	}
	return status
}
