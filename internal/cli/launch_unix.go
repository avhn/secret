//go:build !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/transport"
)

func launchTemplateUnsupported() bool { return false }

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
	process := supervisedProcess{
		wait:    func() int { return childStatus(cmd.Wait()) },
		kill:    func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) },
		forward: func(s os.Signal) { _ = syscall.Kill(-cmd.Process.Pid, s.(syscall.Signal)) },
	}
	return c.superviseChild(process, stdout, stderr, matcher.Filter, signals, 0, 2*time.Second)
}
