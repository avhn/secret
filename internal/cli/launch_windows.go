//go:build windows

package cli

import (
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/transport"
)

// Rendering, console consent and operator persistence are a separate M5a step.
func launchTemplateUnsupported() bool { return true }

// Windows exec is a supervised, unfiltered child, not process replacement.
func (c command) execChild(args, env []string) int {
	return c.windowsChild(args, env, nil, false)
}

func (c command) runChild(args, env []string, values [][]byte) int {
	return c.windowsChild(args, env, values, true)
}

func (c command) windowsChild(args, env []string, values [][]byte, filtered bool) (status int) {
	copyStream := func(r io.Reader, w io.Writer) error {
		_, err := io.Copy(w, r)
		return err
	}
	if filtered {
		matcher, err := transport.NewMatcher(values)
		if err != nil {
			return c.runFailure(err.Error())
		}
		copyStream = matcher.Filter
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	stdout, outWrite, err := os.Pipe()
	if err != nil {
		return c.runFailure("child launch failed")
	}
	defer stdout.Close()
	defer outWrite.Close()
	stderr, errWrite, err := os.Pipe()
	if err != nil {
		return c.runFailure("child launch failed")
	}
	defer stderr.Close()
	defer errWrite.Close()
	select {
	case s := <-signals:
		return 128 + int(s.(syscall.Signal))
	default:
	}
	process, err := transport.StartWindowsProcess(args, env, c.in, outWrite, errWrite)
	if err != nil {
		return c.runFailure(err.Error())
	}
	outWrite.Close()
	errWrite.Close()
	defer func() {
		if process.Close() != nil {
			status = c.runFailure("child supervision failed")
		}
	}()
	child := supervisedProcess{
		wait: func() int {
			code, err := process.Wait()
			if err != nil {
				return 1
			}
			return code
		},
		kill:    process.Kill,
		forward: func(os.Signal) { process.ForwardInterrupt() },
	}
	return c.superviseChild(child, stdout, stderr, copyStream, signals, 15*time.Second, 250*time.Millisecond)
}
