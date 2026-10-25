//go:build windows

package hook

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/input"
	"golang.org/x/sys/windows"
)

func TestWindowsDevelopmentShim(t *testing.T) {
	// Retain the already provisioned build caches before replacing HOME and
	// USERPROFILE, rather than downloading dependencies into the fake profile.
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go.exe")
	cacheOutput, err := exec.Command(goBinary, "env", "GOMODCACHE", "GOCACHE").Output()
	if err != nil {
		t.Fatal(err)
	}
	caches := strings.Split(strings.TrimSpace(string(cacheOutput)), "\n")
	if len(caches) != 2 {
		t.Fatal("native build cache paths unavailable")
	}
	_, work := windowsHookFixture(t)
	root := filepath.Join(t.TempDir(), "development tools ! with spaces")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../hooks/guard-go.cmd")
	if err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(root, "guard-go.cmd")
	if err := os.WriteFile(shim, data, 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "secret.exe")
	build := exec.Command(goBinary, "build", "-buildvcs=false", "-mod=readonly", "-o", binary, "./cmd/secret")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOMODCACHE="+strings.TrimSpace(caches[0]), "GOCACHE="+strings.TrimSpace(caches[1]))
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native development fixture: %v (%s)", err, output)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(payload string) *exec.Cmd {
		cmd := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", shim)
		cmd.Stdin = strings.NewReader(payload)
		cmd.Dir = work
		return cmd
	}
	cwd := strings.ReplaceAll(filepath.ToSlash(work), `"`, `\"`)
	payload := `{"tool_name":"Bash","cwd":"` + cwd + `","tool_input":{"command":"echo public"}}`
	// No PATH lookup can satisfy the fixed sibling reference.
	t.Setenv("PATH", "")
	t.Setenv("ERRORLEVEL", "77")
	cmd := invoke(payload)
	output, err := cmd.Output()
	if err != nil || !bytes.Equal(bytes.TrimSpace(output), bytes.TrimSpace(input.Deny(windowsShellReason, true))) {
		t.Fatalf("native sibling invocation failed: %v (%s)", err, output)
	}
	planted := filepath.Join(root, "planted")
	if err := os.Mkdir(planted, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(binary, filepath.Join(planted, "secret.exe")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", planted)
	cmd = invoke(payload)
	output, err = cmd.Output()
	missing := input.Deny("secret: development binary unavailable; build hooks/secret.exe", false)
	if err != nil || !bytes.Equal(bytes.TrimSpace(output), bytes.TrimSpace(missing)) {
		t.Fatalf("missing sibling did not deny independently of PATH: %v (%s)", err, output)
	}
	readOnly, err := os.Open(shim)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	cmd = invoke(payload)
	cmd.Stdout = readOnly
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(stderr.String(), "secret: development binary unavailable") {
		t.Fatalf("missing-binary output failure did not propagate: %v (%s)", err, stderr.Bytes())
	}
}
