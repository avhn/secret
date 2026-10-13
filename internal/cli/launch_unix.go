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

func (c command) runChild(args, env []string, values [][]byte) int {
	matcher, e := transport.NewMatcher(values)
	if e != nil {
		return c.failure(e)
	}
	path, e := childPath(args[0], env)
	if e != nil {
		return c.fail("child launch failed", 1)
	}
	cmd := exec.Command(path, args[1:]...)
	cmd.Args[0] = args[0]
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
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
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
	go func() { filters <- matcher.Filter(stdout, timedWriter{c.out}) }()
	go func() { filters <- matcher.Filter(stderr, timedWriter{c.errOut}) }()
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
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = stdout.Close()
			_ = stderr.Close()
			return c.fail("redaction filter failed", 1)
		}
	}
	if failed {
		return c.fail("redaction filter failed", 1)
	}
	return childStatus(status)
}
