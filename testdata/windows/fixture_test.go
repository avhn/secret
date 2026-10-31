//go:build windows && windowsfixture

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsLauncherPIDPublication(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "child.pid")
	if err := writeLauncherPID(path, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != strconv.Itoa(os.Getpid()) {
		t.Fatal("published PID was not complete")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("PID publication left scratch files")
	}
	blocked := filepath.Join(dir, "directory")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeLauncherPID(blocked, os.Getpid()); err == nil {
		t.Fatal("PID publication replaced a directory")
	}
	entries, err = os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatal("failed PID publication left scratch files")
	}
}

func TestWindowsLauncherRejectsInvalidRequests(t *testing.T) {
	for _, req := range []request{
		{Executable: "relative.exe", Path: t.TempDir()},
		{Executable: `C:\synthetic\missing.exe`, Path: "relative"},
		{Executable: `C:\synthetic\missing.exe`, Path: t.TempDir(), Value: []byte("synthetic")},
		{Executable: `C:\synthetic\missing.exe`, Path: t.TempDir(), Reference: "wincred:forbidden"},
		{Executable: `C:\synthetic\missing.exe`, Path: t.TempDir(), Args: []string{"unexpected"}},
	} {
		if _, err := launcherLifecycle(req); err == nil {
			t.Fatal("invalid lifecycle request accepted")
		}
	}
}

func TestWindowsLauncherLifecycle(t *testing.T) {
	// Fresh production CLI and test-only fixture, without the hosted provider gate.
	root := testutil.TempDir(t)
	source, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	image, fixture := filepath.Join(root, "secret.exe"), filepath.Join(root, "fixture.exe")
	for _, args := range [][]string{
		{"build", "-o", image, "./cmd/secret"},
		{"build", "-tags", "windowsfixture", "-o", fixture, "./testdata/windows"},
	} {
		build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), args...)
		build.Dir = source
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build synthetic launcher inputs: %v\n%s", err, output)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	data, err := json.Marshal(request{Mode: "launcher", Executable: image, Path: root})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, fixture)
	cmd.Dir = root
	cmd.Stdin = bytes.NewReader(data)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "GITHUB_ACTIONS") && !strings.EqualFold(key, "RUNNER_OS") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	// Enable only the test fixture's hosted dispatch for this synthetic child.
	// Launcher mode never touches CredMan; journalPath still independently
	// requires SECRET_REQUIRE_WINCRED before any provider fixture operation.
	cmd.Env = append(cmd.Env, "GITHUB_ACTIONS=true", "RUNNER_OS=Windows")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("synthetic production launcher lifecycle failed: %v\n%s", err, stderr.Bytes())
	}
	var got result
	if json.Unmarshal(stdout.Bytes(), &got) != nil || got.Code != 0 || len(got.Output) != 0 || stderr.Len() != 0 {
		t.Fatal("lifecycle fixture returned unexpected output")
	}
}

func TestSyntheticTarget(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "123")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Setenv("GITHUB_JOB", "windows-cli")
	service := "secret/m5a-cli-123-2-windows-cli-" + strings.Repeat("a", 32)
	account := strings.Repeat("b", 32)
	for _, tc := range []struct {
		name, target string
		valid        bool
	}{
		{"exact", service + "/" + account, true},
		{"legacy lane", "secret/m5a-ci-" + strings.Repeat("a", 32) + "/" + account, false},
		{"real service", "secret/production/" + account, false},
		{"different run", "secret/m5a-cli-124-2-windows-cli-" + strings.Repeat("a", 32) + "/" + account, false},
		{"wildcard", service + "/*", false},
		{"adjacent", service + "-adjacent/" + account, false},
		{"uppercase account", service + "/" + strings.ToUpper(account), false},
		{"short account", service + "/a", false},
		{"short service", "secret/m5a-cli-a/" + account, false},
		{"extra segment", service + "/" + account + "/extra", false},
		{"NUL", service + "/" + account[:31] + "\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if syntheticTarget(tc.target) != tc.valid {
				t.Fatal("exact synthetic target validation mismatch")
			}
		})
	}
}

func TestConsoleRejectsInvalidRequestsBeforeCreation(t *testing.T) {
	for _, req := range []request{
		{Executable: "relative.exe", Prompt: "TOKEN: ", Value: []byte("synthetic")},
		{Executable: `C:\synthetic\missing.exe`, Value: []byte("synthetic")},
		{Executable: `C:\synthetic\missing.exe`, Prompt: "TOKEN: "},
		{Mode: "get", Executable: `C:\synthetic\missing.exe`},
		{Executable: `C:\synthetic\missing.exe`, Prompt: "TOKEN: ", Value: []byte("bad\ninput")},
	} {
		if _, err := console(req); err == nil {
			t.Fatal("invalid console request accepted")
		}
	}
}

func TestJournalRequiresHostedProviderGate(t *testing.T) {
	t.Setenv("SECRET_REQUIRE_WINCRED", "")
	t.Setenv("RUNNER_TEMP", t.TempDir())
	if _, err := journalPath(); err == nil {
		t.Fatal("provider access accepted without explicit gate")
	}
	t.Setenv("SECRET_REQUIRE_WINCRED", "1")
	t.Setenv("RUNNER_TEMP", "relative")
	if _, err := journalPath(); err == nil {
		t.Fatal("relative journal root accepted")
	}
}

func TestConsolePromptSeen(t *testing.T) {
	for _, tc := range []struct {
		output, prompt string
		seen           bool
	}{
		{"TOKEN: ", "TOKEN: ", true},
		{"\x1b[2JTOKEN:\x1b[8G", "TOKEN: ", true},
		{"TOKEN", "TOKEN: ", false},
		{"", "TOKEN: ", false},
		{"anything", " ", false},
	} {
		if consolePromptSeen([]byte(tc.output), tc.prompt) != tc.seen {
			t.Fatal("console prompt marker mismatch")
		}
	}
}
