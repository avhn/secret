package policy

import (
	"context"
	"io"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"
)

// External tools are used only for disposable GNU sed evidence. Analyzer inputs
// are never executed. Bound direct processes and inherited output-pipe lifetime.
func syntheticCommand(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = nil
	cmd.WaitDelay = time.Second
	return cmd
}

// This child executes only this test binary, not any inspected shell source.
func TestSyntheticCommandProcess(t *testing.T) {
	if !slices.Contains(os.Args, "secret-hook-synthetic-command-child") {
		return
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil || len(data) != 0 {
		t.Fatalf("expected empty synthetic stdin: %v", err)
	}
	if _, err := io.WriteString(os.Stdout, "synthetic stdout\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(os.Stderr, "synthetic stderr\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

func TestSyntheticCommandDeadline(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := syntheticCommand(t, binary, "-test.run=^TestSyntheticCommandProcess$", "--", "secret-hook-synthetic-command-child")
	if cmd.Stdin != nil || cmd.WaitDelay != time.Second {
		t.Fatal("synthetic command must bound stdin and pipe waits")
	}
	started := time.Now()
	output, err := cmd.CombinedOutput()
	elapsed := time.Since(started)
	if err == nil || elapsed < 9*time.Second || elapsed > 15*time.Second {
		t.Fatalf("synthetic child was not stopped at its deadline: elapsed=%s error=%v", elapsed, err)
	}
	if string(output) != "synthetic stdout\nsynthetic stderr\n" {
		t.Fatalf("synthetic output was not captured: %q", output)
	}
}
