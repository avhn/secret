package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/store"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// blockingWriter simulates a caller that never drains filtered output.
type blockingWriter struct{ blocked chan struct{} }

func (w blockingWriter) Write([]byte) (int, error) { <-w.blocked; return 0, nil }

func TestRunBlockedOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix child supervision required")
	}
	var errOut bytes.Buffer
	blocked := make(chan struct{})
	defer close(blocked)
	c := command{in: os.Stdin, out: blockingWriter{blocked}, errOut: &errOut}
	start := time.Now()
	status := c.runChild([]string{"sh", "-c", "printf synthetic-token; sleep 10"}, os.Environ(), [][]byte{[]byte("synthetic-token")})
	if status != 1 || !strings.Contains(errOut.String(), "redaction filter failed") || time.Since(start) > 4*time.Second {
		t.Fatalf("status %d stderr %q elapsed %s", status, errOut.String(), time.Since(start))
	}
}

func TestChildPathFromSelectedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable mode and PATH required")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "synthetic-command")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf synthetic-command"), 0700); err != nil {
		t.Fatal(err)
	}
	selection := store.Selection{Keys: []string{"PATH"}, Matched: map[string]store.Record{"PATH": {Value: []byte(dir)}}}
	env, err := childEnvironment([]string{"PATH=/nonexistent"}, selection, nil, nil, "fallback")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	c := command{in: os.Stdin, out: &out, errOut: &errOut}
	if got := c.runChild([]string{"synthetic-command"}, env, nil); got != 0 || out.String() != "synthetic-command" {
		t.Fatalf("status %d stdout %q stderr %q", got, out.String(), errOut.String())
	}
}

// A descendant which closed both pipes must not survive even when the child and
// both filters finished successfully. File existence is checked only on synthetic
// paths; the delayed marker independently detects a surviving descendant.
func TestTemplatePipeClosingDescendants(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process groups required")
	}
	for _, exit := range []string{"0", "37"} {
		t.Run(exit, func(t *testing.T) {
			home := syntheticTemplateHome(t)
			t.Setenv("HOME", home)
			t.Setenv("SECRETS_DIR", filepath.Join(home, "overridden"))
			storePath := filepath.Join(home, "synthetic.store")
			templatePath := filepath.Join(home, "synthetic.tmpl")
			marker := filepath.Join(home, "survived")
			if err := os.WriteFile(storePath, []byte("KEY=synthetic-token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(templatePath, []byte("{{KEY}}"), 0600); err != nil {
				t.Fatal(err)
			}
			var out, errOut bytes.Buffer
			script := `(sleep 0.4; test -e "$SECRET_TEMPLATE_FILE" || printf survived > "$1") </dev/null >/dev/null 2>&1 & exit "$2"`
			status := Main([]string{"run", "-f", "file:" + storePath, "--template-file", templatePath, "--", "sh", "-c", script, "sh", marker, exit}, os.Stdin, &out, &errOut)
			want := 0
			if exit == "37" {
				want = 37
			}
			if status != want || errOut.Len() != 0 {
				t.Fatalf("status %d stderr %q", status, errOut.String())
			}
			<-time.After(700 * time.Millisecond)
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pipe-closing descendant survived template cleanup")
			}
			entries, err := os.ReadDir(filepath.Join(home, ".secrets", ".rendered"))
			if err != nil || len(entries) != 0 {
				t.Fatal("rendered payload survived child completion")
			}
		})
	}
}

func TestTemplateSignalCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix process groups required")
	}
	if os.Getenv("SECRET_SYNTHETIC_TEMPLATE_SIGNAL_HELPER") == "1" {
		script := `trap '' INT TERM HUP QUIT; printf '%s\n' "$SECRET_TEMPLATE_FILE"; printf '%0128d\n' 0; while :; do sleep 10; done`
		os.Exit(Main([]string{"run", "-f", "file:" + os.Getenv("SECRET_SYNTHETIC_STORE"), "--template-file", os.Getenv("SECRET_SYNTHETIC_TEMPLATE"), "--", "sh", "-c", script}, os.Stdin, os.Stdout, os.Stderr))
	}
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(sig.String(), func(t *testing.T) {
			home := syntheticTemplateHome(t)
			storePath := filepath.Join(home, "synthetic.store")
			templatePath := filepath.Join(home, "synthetic.tmpl")
			if err := os.WriteFile(storePath, []byte("KEY=synthetic-token\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(templatePath, []byte("{{KEY}}"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTemplateSignalCleanup$")
			cmd.Env = append(os.Environ(), "HOME="+home, "SECRETS_DIR="+filepath.Join(home, "overridden"), "SECRET_SYNTHETIC_TEMPLATE_SIGNAL_HELPER=1", "SECRET_SYNTHETIC_STORE="+storePath, "SECRET_SYNTHETIC_TEMPLATE="+templatePath)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var errOut bytes.Buffer
			cmd.Stderr = &errOut
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(stdout)
			path, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			path = strings.TrimSuffix(path, "\n")
			if filepath.Dir(filepath.Dir(path)) != filepath.Join(home, ".secrets", ".rendered") {
				t.Fatal("helper did not expose synthetic template path")
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, reader)
			err = cmd.Wait()
			var status *exec.ExitError
			if !errors.As(err, &status) || status.ExitCode() != 128+int(sig) || ctx.Err() != nil {
				t.Fatalf("signal result %v stderr %q", err, errOut.String())
			}
			if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("catchable signal left plaintext behind")
			}
		})
	}
}

func TestTemplateStalledStderrCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix supervision required")
	}
	home := syntheticTemplateHome(t)
	t.Setenv("HOME", home)
	storePath := filepath.Join(home, "synthetic.store")
	templatePath := filepath.Join(home, "synthetic.tmpl")
	if err := os.WriteFile(storePath, []byte("KEY=synthetic-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templatePath, []byte("{{KEY}}"), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan struct{})
	defer close(blocked)
	start := time.Now()
	status := Main([]string{"run", "-f", "file:" + storePath, "--template-file", templatePath, "--", "sh", "-c", `cat "$SECRET_TEMPLATE_FILE" >&2; sleep 10`}, os.Stdin, io.Discard, blockingWriter{blocked})
	if status != 1 || time.Since(start) > 6*time.Second {
		t.Fatalf("stalled stderr status %d elapsed %s", status, time.Since(start))
	}
	entries, err := os.ReadDir(filepath.Join(home, ".secrets", ".rendered"))
	if err != nil || len(entries) != 0 {
		t.Fatal("stalled stderr kept plaintext alive")
	}
}

func TestTemplatePendingSignalBeforeSpawn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix template supervision")
	}
	home := syntheticTemplateHome(t)
	rendered, err := feature.RenderTemplate(home, []byte("{{KEY}}"), map[string][]byte{"KEY": []byte("synthetic-token")})
	if err != nil {
		t.Fatal(err)
	}
	defer rendered.Close()
	marker := filepath.Join(home, "spawned")
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGTERM
	var out, errOut bytes.Buffer
	c := command{in: os.Stdin, out: &out, errOut: &errOut}
	supervisor, ok := any(c).(templateSupervisor)
	if !ok {
		t.Fatal("missing Unix template supervisor")
	}
	status := supervisor.runTemplateChild([]string{"sh", "-c", `printf spawned > "$1"`, "sh", marker}, os.Environ(), nil, signals)
	if err := rendered.Close(); err != nil {
		t.Fatal(err)
	}
	if status != 143 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("pending signal status %d", status)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending signal allowed child spawn")
	}
	if _, err := os.Stat(filepath.Dir(rendered.Path())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending signal left plaintext behind")
	}
}
