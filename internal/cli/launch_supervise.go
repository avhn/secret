package cli

import (
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

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

type supervisedProcess struct {
	wait    func() int
	kill    func()
	forward func(os.Signal)
	// Windows relay exec alone bounds shutdown independently of normal lifetime.
	shutdownWait time.Duration
	// Windows exec shares one diagnostic reporter across relay and native cleanup.
	failure func(string) int
}

// superviseChild relays both streams, never using a raw-output fallback.
// Callers select runtime and inherited-pipe bounds; zero maxRun is unlimited.
// Unix and filtered Windows run retain their existing supervision policies.
func (c command) superviseChild(process supervisedProcess, stdout, stderr *os.File, copyStream func(io.Reader, io.Writer) error, signals <-chan os.Signal, maxRun, pipeWait time.Duration) int {
	failure := c.runFailure
	if process.failure != nil {
		failure = process.failure
	}
	defer stdout.Close()
	defer stderr.Close()
	// Descendants may close both pipes and outlive the direct child.
	defer process.kill()
	filters := make(chan error, 2)
	go func() { filters <- copyStream(stdout, timedWriter{c.out}) }()
	go func() { filters <- copyStream(stderr, timedWriter{c.errOut}) }()
	waited := make(chan int, 1)
	go func() { waited <- process.wait() }()
	var drain, terminate, deadline, shutdown <-chan time.Time
	var timeout, signalTimeout, runtimeTimeout, shutdownTimeout *time.Timer
	startShutdown := func() {
		if process.shutdownWait > 0 && shutdownTimeout == nil {
			shutdownTimeout = time.NewTimer(process.shutdownWait)
			shutdown = shutdownTimeout.C
		}
	}
	if maxRun > 0 {
		runtimeTimeout = time.NewTimer(maxRun)
		deadline = runtimeTimeout.C
	}
	defer func() {
		for _, timer := range []*time.Timer{timeout, signalTimeout, runtimeTimeout, shutdownTimeout} {
			if timer != nil {
				timer.Stop()
			}
		}
	}()
	received, status, interrupted := 0, 0, 0
	failed, waitDone := false, false
	for received < 2 || !waitDone {
		select {
		case s := <-signals:
			process.forward(s)
			if interrupted == 0 {
				interrupted = 128 + int(s.(syscall.Signal))
				signalTimeout = time.NewTimer(2 * time.Second)
				terminate = signalTimeout.C
			}
		case <-terminate:
			terminate = nil
			startShutdown()
			process.kill()
		case er := <-filters:
			received++
			if er != nil {
				failed = true
				startShutdown()
				process.kill()
				_ = stdout.Close()
				_ = stderr.Close()
			}
		case status = <-waited:
			waitDone = true
			if received < 2 {
				timeout = time.NewTimer(pipeWait)
				drain = timeout.C
			}
		case <-drain:
			process.kill()
			_ = stdout.Close()
			_ = stderr.Close()
			return failure("redaction filter failed")
		case <-shutdown:
			// Reach the caller's checked native Close even if wait never notifies.
			if failed {
				return failure("redaction filter failed")
			}
			return interrupted
		case <-deadline:
			process.kill()
			_ = stdout.Close()
			_ = stderr.Close()
			return failure("child supervision timed out")
		}
	}
	if failed {
		return failure("redaction filter failed")
	}
	if interrupted != 0 {
		return interrupted
	}
	return status
}
