//go:build !windows

package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/transport"
)

func launchUnsupported() bool { return false }

// childPath looks up bare names in the constructed environment, not the parent's PATH.
func childPath(name string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return name, nil
	}
	path := "/bin:/usr/bin"
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
		}
	}
	for _, dir := range filepath.SplitList(path) {
		candidate := filepath.Join(dir, name)
		if dir == "" || dir == "." {
			candidate = "./" + name
		}
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func (c command) execChild(args, env []string) int {
	path, e := childPath(args[0], env)
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

// timedWriter leaves at most one blocked writer behind and never bypasses filtering.
type timedWriter struct{ out io.Writer }

func (w timedWriter) Write(p []byte) (int, error) {
	result := make(chan struct {
		n   int
		err error
	}, 1)
	go func() {
		n, err := w.out.Write(p)
		result <- struct {
			n   int
			err error
		}{n, err}
	}()
	select {
	case r := <-result:
		return r.n, r.err
	case <-time.After(2 * time.Second):
		return 0, errors.New("redaction output stalled")
	}
}

// A stalled stderr consumer must not hold template cleanup behind diagnostics.
func (c command) runFailure(message string) int {
	_, _ = (timedWriter{c.errOut}).Write([]byte("secret: " + message + "\n"))
	return 1
}

func (c command) runChild(args, env []string, values [][]byte) int {
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	return c.runTemplateChild(args, env, values, signals)
}

func (c command) runTemplateChild(args, env []string, values [][]byte, signals <-chan os.Signal) int {
	matcher, e := transport.NewMatcher(values)
	if e != nil {
		return c.runFailure(e.Error())
	}
	path, e := childPath(args[0], env)
	if e != nil {
		return c.runFailure("child launch failed")
	}
	cmd := exec.Command(path, args[1:]...)
	cmd.Args[0] = args[0]
	cmd.Env = env
	cmd.Stdin = c.in
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, outWrite, e := os.Pipe()
	if e != nil {
		return c.runFailure("redaction filter failed")
	}
	stderr, errWrite, e := os.Pipe()
	if e != nil {
		stdout.Close()
		outWrite.Close()
		return c.runFailure("redaction filter failed")
	}
	cmd.Stdout = outWrite
	cmd.Stderr = errWrite
	select {
	case s := <-signals:
		stdout.Close()
		stderr.Close()
		outWrite.Close()
		errWrite.Close()
		return 128 + int(s.(syscall.Signal))
	default:
	}
	if e = cmd.Start(); e != nil {
		stdout.Close()
		stderr.Close()
		outWrite.Close()
		errWrite.Close()
		return c.runFailure("child launch failed")
	}
	outWrite.Close()
	errWrite.Close()
	defer stdout.Close()
	defer stderr.Close()
	// A descendant can close both pipes and outlive the direct child. Always
	// stop the process group before returning, including successful completion,
	// so the caller can remove a template only after explicit group shutdown.
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	filters := make(chan error, 2)
	go func() { filters <- matcher.Filter(stdout, timedWriter{c.out}) }()
	go func() { filters <- matcher.Filter(stderr, timedWriter{c.errOut}) }()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var drain, terminate <-chan time.Time
	var timeout, signalTimeout *time.Timer
	defer func() {
		if timeout != nil {
			timeout.Stop()
		}
		if signalTimeout != nil {
			signalTimeout.Stop()
		}
	}()
	received := 0
	failed := false
	var status error
	waitDone := false
	interrupted := 0
	for received < 2 || !waitDone {
		select {
		case s := <-signals:
			sig := s.(syscall.Signal)
			_ = syscall.Kill(-cmd.Process.Pid, sig)
			if interrupted == 0 {
				interrupted = 128 + int(sig)
				signalTimeout = time.NewTimer(2 * time.Second)
				terminate = signalTimeout.C
			}
		case <-terminate:
			// Do not let an ignored catchable signal keep plaintext alive.
			terminate = nil
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
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
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = stdout.Close()
			_ = stderr.Close()
			return c.runFailure("redaction filter failed")
		}
	}
	if failed {
		return c.runFailure("redaction filter failed")
	}
	if interrupted != 0 {
		return interrupted
	}
	return childStatus(status)
}
