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
	before, err := operatorTerminalState(int(os.Stdin.Fd()))
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
		after, err := operatorTerminalState(int(os.Stdin.Fd()))
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
	if mode == "diagnostic-failure" {
		// Fault injection proves stderr capture and synthetic input redaction.
		fmt.Fprintln(os.Stderr, "synthetic stderr diagnostic sentinel")
		_, _ = os.Stderr.Write(bytes.Repeat([]byte{'s'}, 64))
		t.Fatal("synthetic PTY diagnostic sentinel")
	}
	fmt.Println("OPERATOR_PTY_OK")
	if mode == "exit-drain" {
		// Exceed the PTY output queue after the marker. Waiting for exit without
		// draining now deadlocks even on Linux, independent of packet timing.
		_, _ = os.Stdout.Write(bytes.Repeat([]byte{'d'}, 128<<10))
		fmt.Println("OPERATOR_PTY_DRAINED")
	}
	if mode == "exit-timeout" {
		time.Sleep(time.Hour) // Synthetic stalled exit; the driver must kill and reap.
	}
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
	for _, mode := range []string{"long-value", "limit", "overflow", "overflow-edit", "cancel", "long-confirmation", "confirmation-overflow", "exit-drain", "diagnostic-failure", "input-timeout", "exit-timeout"} {
		t.Run(mode, func(t *testing.T) {
			// The driver has a 20-second overall deadline, including writes and
			// exit draining. Leave time for its bounded kill/reap diagnostics.
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, python, "-I", "-c", operatorPTYDriver, binary, mode)
			// Even accidental future discovery in the helper stays in a disposable HOME.
			home := t.TempDir()
			cmd.Env = append(os.Environ(), "HOME="+home, "SECRETS_DIR="+filepath.Join(home, ".secrets"), "SECRETS_ENV="+filepath.Join(home, ".secrets.env"))
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("disposable PTY driver exceeded its overall deadline: %v\n%s", ctx.Err(), output)
			}
			if mode == "input-timeout" || mode == "exit-timeout" {
				marker := "input timed out"
				if mode == "exit-timeout" {
					marker = "helper exit timed out"
				}
				if err == nil || !bytes.Contains(output, []byte(marker)) || !bytes.Contains(output, []byte("helper exit code: -9")) || bytes.Contains(output, bytes.Repeat([]byte{'s'}, 32)) {
					t.Fatalf("disposable PTY timeout diagnostic missing or unsafe: %v\n%s", err, output)
				}
				return
			}
			if mode == "diagnostic-failure" {
				if err == nil || bytes.Contains(output, bytes.Repeat([]byte{'s'}, 32)) {
					t.Fatalf("disposable PTY failure diagnostic missing or unsafe: %v\n%s", err, output)
				}
				for _, marker := range []string{"helper exit code: 1", "synthetic PTY diagnostic sentinel", "synthetic stderr diagnostic sentinel", "<synthetic input redacted>"} {
					if !bytes.Contains(output, []byte(marker)) {
						t.Fatalf("disposable PTY failure diagnostic missing %q: %s", marker, output)
					}
				}
				return
			}
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
import re
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

os.set_blocking(master, False)
transcript = bytearray()
deadline = time.monotonic() + (1 if mode in ("input-timeout", "exit-timeout") else 20)
reaped = False
closed = False
status = None

def remaining(phase):
    timeout = deadline - time.monotonic()
    if timeout <= 0:
        raise RuntimeError("disposable PTY " + phase + " timed out")
    return min(timeout, 0.05)

def receive(timeout):
    global closed
    if closed or not select.select([master], [], [], timeout)[0]:
        return False
    try:
        chunk = os.read(master, 65536)
    except BlockingIOError:
        return False
    except OSError as exc:
        if exc.errno != errno.EIO:
            raise
        chunk = b""
    if not chunk:
        closed = True
        return False
    transcript.extend(chunk)
    if len(transcript) > 1 << 20:
        raise RuntimeError("disposable PTY output exceeded test bound")
    return True

def receive_until(marker):
    while marker not in transcript:
        receive(remaining("prompt"))
        if closed and marker not in transcript:
            raise RuntimeError("disposable PTY helper exited before completing")

def send(data):
    flags = termios.tcgetattr(master)[3]
    if flags & (termios.ICANON | termios.ECHO):
        raise RuntimeError("hidden prompt appeared before noncanonical, no-echo mode")
    view = memoryview(data)
    while view:
        readable, writable, _ = select.select([master], [master], [], remaining("input"))
        if readable:
            receive(0)
        if writable:
            try:
                count = os.write(master, view[:4096])
            except BlockingIOError:
                continue
            view = view[count:]

def reap_until(until):
    global reaped, status
    while not reaped:
        waited, status = os.waitpid(pid, os.WNOHANG)
        reaped = bool(waited)
        if reaped:
            while receive(0):
                pass
            return True
        timeout = min(until - time.monotonic(), 0.05)
        if timeout <= 0:
            return False
        # Darwin drains a session leader's controlling-terminal output during
        # exit. Keep consuming after the success marker, including Go's PASS.
        if closed:
            time.sleep(timeout)
        else:
            receive(timeout)
    return True

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
            if mode == "input-timeout":
                # Leave the hidden reader stopped so the raw input queue fills.
                os.kill(pid, signal.SIGSTOP)
                data = b"s" * (2 << 20)
            elif mode == "limit":
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
    if not reap_until(deadline):
        raise RuntimeError("disposable PTY helper exit timed out")
    if b"s" * 32 in transcript:
        raise RuntimeError("synthetic hidden value was echoed")
    if mode == "exit-drain" and b"OPERATOR_PTY_DRAINED" not in transcript:
        raise RuntimeError("disposable PTY trailing output was not drained")
    if status != 0:
        raise RuntimeError("disposable PTY helper failed")
except Exception:
    if not reaped:
        # EOF can precede waitable exit status. Drain while giving a failing
        # helper a brief chance to exit before killing a genuinely stalled one.
        if not reap_until(time.monotonic() + 0.2):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            reap_until(time.monotonic() + 2)
    # stdout and stderr share this disposable PTY. Redact synthetic input and
    # report only a bounded tail, never the input being sent on a stalled write.
    diagnostic = re.sub(b"s{32,}", b"<synthetic input redacted>", bytes(transcript))
    code = os.waitstatus_to_exitcode(status) if reaped else "not reaped before cleanup deadline"
    print("disposable PTY helper exit code:", code, file=sys.stderr)
    print("helper stdout/stderr tail:", repr(diagnostic[-4096:]), file=sys.stderr)
    raise
finally:
    # Closing the master also releases Darwin's exit drain if bounded cleanup
    # could not reap. Never introduce another blocking wait in a failure path.
    os.close(master)
    if not reaped:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        cleanup_deadline = time.monotonic() + 0.5
        while not reaped and time.monotonic() < cleanup_deadline:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            reaped = bool(waited)
            if not reaped:
                time.sleep(0.01)
`
