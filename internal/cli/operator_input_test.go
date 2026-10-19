package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"golang.org/x/term"
)

func TestReadOperatorLine(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		limit             int
		valid             bool
	}{
		{"line feed", "abcd\n", "abcd", 4, true},
		{"return", "abcd\r", "abcd", 4, true},
		{"backspace", "abc\bd\n", "abd", 4, true},
		{"delete", "abcd\x7f\x7f\n", "ab", 4, true},
		{"erase", "abcd\x15xy\n", "xy", 4, true},
		{"empty", "\n", "", 4, true},
		{"overflow", "abcde\n", "", 4, false},
		{"overflow remains after delete", "abcde\x7f\n", "", 4, false},
		{"overflow remains after erase", "abcde\x15xy\n", "", 4, false},
		{"interrupt", "abc\x03", "", 4, false},
		{"end of input", "abc\x04", "", 4, false},
		{"suspend", "abc\x1a", "", 4, false},
		{"quit", "abc\x1c", "", 4, false},
		{"short read", "abc", "", 4, false},
		{"invalid limit", "abc\n", "", 0, false},
		{"oversize limit", "abc\n", "", operatorValueLimit + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := readOperatorLine(strings.NewReader(tc.input), tc.limit)
			defer secure.Clear(value)
			if !tc.valid {
				if err != secure.ErrInput || value != nil {
					t.Fatal("invalid hidden input was accepted")
				}
				return
			}
			if err != nil || !bytes.Equal(value, []byte(tc.want)) {
				t.Fatal("hidden input editing changed accepted bytes")
			}
			if !bytes.Equal(value[len(value):cap(value)], make([]byte, cap(value)-len(value))) {
				t.Fatal("erased hidden bytes remain in the returned allocation")
			}
		})
	}
	reader := strings.NewReader("abcde\nnext\n")
	if _, err := readOperatorLine(reader, 4); err != secure.ErrInput {
		t.Fatal("overflow accepted")
	}
	value, err := readOperatorLine(reader, 4)
	defer secure.Clear(value)
	if err != nil || !bytes.Equal(value, []byte("next")) {
		t.Fatal("overflow suffix was not drained before the next input")
	}
}

// The helper runs with a disposable controlling PTY, never a real store or
// provider. The Python driver writes synthetic bytes only after seeing a prompt.
func TestOperatorPTYHelper(t *testing.T) {
	mode := os.Getenv("SECRET_SYNTHETIC_OPERATOR_PTY")
	if mode == "" {
		return
	}
	before, err := term.GetState(int(os.Stdin.Fd()))
	if err != nil {
		t.Fatal("cannot inspect disposable terminal")
	}
	terminal, err := RequireOperatorTerminal(os.Stdin, os.Stdout)
	if err != nil {
		t.Fatal("disposable terminal gate failed")
	}
	defer terminal.Close()
	request := OperatorRequest{Action: store.ActionRotate, Target: "libsecret:synthetic-pty", Keys: []string{"TOKEN"}}
	if mode == "long-confirmation" {
		request.Action = store.ActionExport
		request.Keys = make([]string, 1000)
		for i := range request.Keys {
			request.Keys[i] = fmt.Sprintf("KEY_%010d", i)
		}
	}
	err = terminal.Confirm(request)
	assertRestored := func() {
		t.Helper()
		after, err := term.GetState(int(os.Stdin.Fd()))
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("hidden input did not restore the terminal state")
		}
	}
	assertRestored()
	if mode == "confirmation-overflow" {
		if err != secure.ErrConsent || terminal.confirmed {
			t.Fatal("oversized confirmation accepted")
		}
	} else {
		if err != nil {
			t.Fatal("exact PTY confirmation declined")
		}
		if mode != "long-confirmation" {
			value, err := terminal.ReadValue()
			defer secure.Clear(value)
			assertRestored()
			if mode == "overflow" || mode == "overflow-edit" || mode == "cancel" {
				if err != secure.ErrInput || value != nil {
					t.Fatal("oversized or cancelled PTY value accepted")
				}
			} else {
				length := 5000
				if mode == "limit" {
					length = operatorValueLimit
				}
				if err != nil || !bytes.Equal(value, bytes.Repeat([]byte{'s'}, length)) {
					t.Fatal("PTY value was truncated or changed")
				}
			}
		}
	}
	if err := terminal.Close(); err != nil {
		t.Fatal("disposable terminal close failed")
	}
	fmt.Println("OPERATOR_PTY_OK")
}

func TestOperatorPTY(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("disposable controlling PTY tests require Linux or macOS")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for disposable PTY tests")
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"long-value", "limit", "overflow", "overflow-edit", "cancel", "long-confirmation", "confirmation-overflow"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-I", "-c", operatorPTYDriver, binary, mode)
			// Even accidental future discovery in the helper stays in a disposable HOME.
			home := t.TempDir()
			cmd.Env = append(os.Environ(), "HOME="+home, "SECRETS_DIR="+filepath.Join(home, ".secrets"), "SECRETS_ENV="+filepath.Join(home, ".secrets.env"))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("disposable PTY check failed: %v\n%s", err, output)
			}
		})
	}
}

const operatorPTYDriver = `
import errno
import os
import pty
import select
import signal
import sys
import termios
import time

binary, mode = sys.argv[1:]
pid, master = pty.fork()
if pid == 0:
    env = dict(os.environ, SECRET_SYNTHETIC_OPERATOR_PTY=mode)
    os.execve(binary, [binary, "-test.run=^TestOperatorPTYHelper$"], env)

transcript = bytearray()
deadline = time.monotonic() + 25
reaped = False

def receive_until(marker):
    while marker not in transcript:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([master], [], [], max(0, remaining))[0]:
            raise RuntimeError("disposable PTY prompt timed out")
        try:
            chunk = os.read(master, 65536)
        except OSError as exc:
            if exc.errno == errno.EIO:
                raise RuntimeError("disposable PTY helper exited before completing") from None
            raise
        if not chunk:
            raise RuntimeError("disposable PTY helper closed before completing")
        transcript.extend(chunk)

def send(data):
    flags = termios.tcgetattr(master)[3]
    if flags & (termios.ICANON | termios.ECHO):
        raise RuntimeError("hidden prompt appeared before noncanonical, no-echo mode")
    view = memoryview(data)
    while view:
        count = os.write(master, view)
        view = view[count:]

try:
    receive_until(b"> ")
    prompt = bytes(transcript).replace(b"\r\n", b"\n")
    challenge = prompt.split(b"input hidden):\n", 1)[1].split(b"\n> ", 1)[0]
    if mode == "long-confirmation" and not 4096 < len(challenge) <= 16384:
        raise RuntimeError("batch confirmation did not exercise a long challenge")
    if mode == "confirmation-overflow":
        send(challenge + b"x\n")
    else:
        send(challenge + b"\n")
        if mode != "long-confirmation":
            receive_until(b"New value (hidden): ")
            if mode == "limit":
                data = b"s" * 65536 + b"\n"
            elif mode == "overflow":
                data = b"s" * 70000 + b"\n"
            elif mode == "overflow-edit":
                data = b"s" * 65537 + b"\x15" + b"s" * 5000 + b"\n"
            elif mode == "cancel":
                data = b"s" * 5000 + b"\x03"
            else:
                data = b"s" * 5000 + b"\n"
            send(data)
    receive_until(b"OPERATOR_PTY_OK")
    if b"s" * 32 in transcript:
        raise RuntimeError("synthetic hidden value was echoed")
    waited, status = os.waitpid(pid, 0)
    reaped = True
    if status != 0:
        raise RuntimeError("disposable PTY helper failed")
finally:
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
    os.close(master)
`
