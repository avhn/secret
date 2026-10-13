//go:build !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/transport"
)

func launchUnsupported() bool { return false }

func (c command) execChild(args, env []string) int {
	path, e := exec.LookPath(args[0])
	if e != nil {
		return c.fail("child launch failed", 1)
	}
	if e = syscall.Exec(path, args, env); e != nil {
		return c.fail("child launch failed", 1)
	}
	return 0
}

func childStatus(e error) int {
	if e == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(e, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exit.ExitCode()
	}
	return 1
}

func (c command) runChild(args, env []string, values [][]byte) int {
	matcher, e := transport.NewMatcher(values)
	if e != nil {
		return c.failure(e)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = env
	cmd.Stdin = c.in
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, outWrite, e := os.Pipe()
	if e != nil {
		return c.fail("redaction filter failed", 1)
	}
	stderr, errWrite, e := os.Pipe()
	if e != nil {
		stdout.Close()
		outWrite.Close()
		return c.fail("redaction filter failed", 1)
	}
	cmd.Stdout = outWrite
	cmd.Stderr = errWrite
	if e = cmd.Start(); e != nil {
		stdout.Close()
		stderr.Close()
		outWrite.Close()
		errWrite.Close()
		return c.fail("child launch failed", 1)
	}
	outWrite.Close()
	errWrite.Close()
	defer stdout.Close()
	defer stderr.Close()
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-signals:
				_ = syscall.Kill(-cmd.Process.Pid, s.(syscall.Signal))
			case <-done:
				return
			}
		}
	}()
	defer close(done)
	filters := make(chan error, 2)
	go func() { filters <- matcher.Filter(stdout, c.out) }()
	go func() { filters <- matcher.Filter(stderr, c.errOut) }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var drain <-chan time.Time
	var timeout *time.Timer
	defer func() {
		if timeout != nil {
			timeout.Stop()
		}
	}()
	received := 0
	failed := false
	var status error
	waitDone := false
	for received < 2 || !waitDone {
		select {
		case er := <-filters:
			received++
			if er != nil {
				failed = true
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				_ = stdout.Close()
				_ = stderr.Close()
			}
		case status = <-waited:
			waitDone = true
			if received < 2 {
				timeout = time.NewTimer(2 * time.Second)
				drain = timeout.C
			}
		case <-drain:
			failed = true
			drain = nil
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = stdout.Close()
			_ = stderr.Close()
		}
	}
	if failed {
		return c.fail("redaction filter failed", 1)
	}
	return childStatus(status)
}
