package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

func TestRunFilterFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix child process groups required")
	}
	var errOut bytes.Buffer
	c := command{in: os.Stdin, out: failingWriter{}, errOut: &errOut}
	started := time.Now()
	status := c.runChild([]string{"sh", "-c", "printf 'synthetic-token'; sleep 10"}, os.Environ(), [][]byte{[]byte("synthetic-token")})
	if status != 1 || !strings.Contains(errOut.String(), "redaction filter failed") || time.Since(started) > 3*time.Second {
		t.Fatalf("status %d stderr %q elapsed %s", status, errOut.String(), time.Since(started))
	}
}

func TestRunDescendantDrain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process groups required")
	}
	var out, errOut bytes.Buffer
	c := command{in: os.Stdin, out: &out, errOut: &errOut}
	start := time.Now()
	status := c.runChild([]string{"sh", "-c", "sleep 10 & printf synthetic-token"}, os.Environ(), [][]byte{[]byte("synthetic-token")})
	if status != 1 || out.String() != "<redacted>" || !strings.Contains(errOut.String(), "redaction filter failed") || time.Since(start) > 4*time.Second {
		t.Fatalf("status %d stdout %q stderr %q elapsed %s", status, out.String(), errOut.String(), time.Since(start))
	}
}

func TestRunStatus(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal exit mapping required")
	}
	for _, tc := range []struct {
		script string
		want   int
	}{{"exit 37", 37}, {"kill -TERM $$", 143}, {"kill -INT $$", 130}, {"kill -HUP $$", 129}} {
		var out, errOut bytes.Buffer
		c := command{in: os.Stdin, out: &out, errOut: &errOut}
		if got := c.runChild([]string{"sh", "-c", tc.script}, os.Environ(), nil); got != tc.want {
			t.Errorf("%s: status %d want %d, stderr %q", tc.script, got, tc.want, errOut.String())
		}
	}
}

func TestRunForwardsSignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix signal forwarding required")
	}
	if os.Getenv("SECRET_SYNTHETIC_HELPER") == "1" {
		c := command{in: os.Stdin, out: io.Discard, errOut: os.Stderr}
		os.Exit(c.runChild([]string{"sh", "-c", "echo ready >&2; exec sleep 10"}, os.Environ(), nil))
	}
	// Helper is a real subprocess so sending TERM does not affect the test runner.
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunForwardsSignal$")
	cmd.Env = append(os.Environ(), "SECRET_SYNTHETIC_HELPER=1")
	stderr, e := cmd.StderrPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	ready := make([]byte, 6)
	if _, e = io.ReadFull(stderr, ready); e != nil {
		t.Fatal(e)
	}
	if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	e = cmd.Wait()
	var status *exec.ExitError
	if !errors.As(e, &status) || status.ExitCode() != 143 {
		t.Fatalf("forwarded status: %v", e)
	}
}
