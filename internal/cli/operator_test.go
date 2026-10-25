package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

type fakeOperatorConsole struct {
	bytes.Buffer
	inputs   [][]byte
	readErr  error
	writeErr error
	closeErr error
	reads    int
	closes   int
}

func (console *fakeOperatorConsole) Write(data []byte) (int, error) {
	if console.writeErr != nil {
		return 0, console.writeErr
	}
	return console.Buffer.Write(data)
}

func (console *fakeOperatorConsole) WriteString(text string) (int, error) {
	return console.Write([]byte(text))
}

func (console *fakeOperatorConsole) readPassword(prompt string, limit int) ([]byte, error) {
	if _, err := console.WriteString(prompt); err != nil {
		return nil, secure.ErrTerminal
	}
	console.reads++
	if len(console.inputs) == 0 {
		return nil, io.EOF
	}
	value := console.inputs[0]
	console.inputs = console.inputs[1:]
	return value, console.readErr
}

func (console *fakeOperatorConsole) Close() error {
	console.closes++
	return console.closeErr
}

func syntheticOperatorRequest(t *testing.T) OperatorRequest {
	t.Helper()
	return OperatorRequest{Action: store.ActionRotate, Target: "file:" + filepath.Join(t.TempDir(), "synthetic.store"), Keys: []string{"TOKEN"}, Labels: map[string]string{"zone": "a", "env": "prod"}}
}

func assertClearedOperatorBytes(t *testing.T, value []byte) {
	t.Helper()
	if !bytes.Equal(value[:cap(value)], make([]byte, cap(value))) {
		t.Fatal("owned terminal input was not cleared")
	}
}

func TestOperatorRefusesBeforeAccess(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "synthetic-stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, tc := range []struct {
		name                string
		in                  *os.File
		out                 io.Writer
		stdinTTY, stdoutTTY bool
	}{
		{"nil stdin", nil, file, true, true},
		{"nil stdout", file, (*os.File)(nil), true, true},
		{"writer stdout", file, &bytes.Buffer{}, true, true},
		{"stdin not tty", file, file, false, true},
		{"stdout not tty", file, file, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checks, opens, accesses := 0, 0, 0
			terminal, err := requireOperatorTerminal(tc.in, tc.out, operatorTerminalOps{
				isTerminal: func(*os.File) bool {
					checks++
					if checks == 1 {
						return tc.stdinTTY
					}
					return tc.stdoutTTY
				},
				open: func() (operatorConsole, error) { opens++; return &fakeOperatorConsole{}, nil },
			})
			if err == nil {
				accesses++
				_ = terminal.Close()
			}
			if err != secure.ErrTerminalRequired || opens != 0 || accesses != 0 {
				t.Fatal("nonterminal invocation reached terminal open or store-access boundary")
			}
		})
	}
	accesses := 0
	err = WithOperatorConsent(file, &bytes.Buffer{}, syntheticOperatorRequest(t), func(*OperatorTerminal) error { accesses++; return nil })
	want := secure.ErrTerminalRequired
	if err != want || accesses != 0 {
		t.Fatal("public boundary invoked store callback without real terminals")
	}
}

func TestOperatorTerminalOpenCleanup(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "synthetic-terminal")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	console := &fakeOperatorConsole{}
	terminal, err := requireOperatorTerminal(file, file, operatorTerminalOps{
		isTerminal: func(*os.File) bool { return true },
		open:       func() (operatorConsole, error) { return console, errors.New("synthetic provider stderr") },
	})
	if terminal != nil || err != secure.ErrTerminal || console.closes != 1 {
		t.Fatal("terminal-open failure leaked handle or diagnostic")
	}
}

func TestOperatorConsentExactAndHidden(t *testing.T) {
	request := syntheticOperatorRequest(t)
	challenge, err := operatorChallenge(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(challenge, []byte("keys=TOKEN labels=env=prod,zone=a")) {
		t.Fatal("confirmation omitted exact key or canonical labels")
	}
	for _, answerKind := range []string{"exact", "yes", "wrong target", "wrong key", "wrong labels", "eof"} {
		t.Run(answerKind, func(t *testing.T) {
			answer := secure.Clone(challenge)
			switch answerKind {
			case "yes":
				answer = []byte("yes")
			case "wrong target":
				answer = bytes.ReplaceAll(answer, []byte("synthetic.store"), []byte("other.store"))
			case "wrong key":
				answer = bytes.ReplaceAll(answer, []byte("TOKEN"), []byte("OTHER"))
			case "wrong labels":
				answer = bytes.ReplaceAll(answer, []byte("env=prod"), []byte("env=qa"))
			}
			console := &fakeOperatorConsole{inputs: [][]byte{answer}}
			if answerKind == "eof" {
				console.readErr = io.EOF
			}
			terminal := &OperatorTerminal{console: console}
			defer terminal.Close()
			accesses := 0
			err := terminal.withConsent(request, func(*OperatorTerminal) error { accesses++; return nil })
			if answerKind == "exact" {
				if err != nil || accesses != 1 || !terminal.confirmed {
					t.Fatal("exact confirmation refused")
				}
			} else if err != secure.ErrConsent || accesses != 0 || terminal.confirmed {
				t.Fatal("incorrect confirmation reached store-access callback")
			}
			if console.reads != 1 || !strings.Contains(console.String(), "input hidden") {
				t.Fatal("confirmation did not use hidden controlling-terminal input")
			}
			assertClearedOperatorBytes(t, answer)
		})
	}
}

func TestOperatorHiddenValueOwnershipAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name              string
		value             []byte
		readErr, writeErr error
		valid             bool
	}{
		{"valid", []byte("synthetic-hidden-value"), nil, nil, true},
		{"trailing lf", []byte("synthetic-hidden-value\n"), nil, nil, true},
		{"empty", nil, nil, nil, false},
		{"nul", []byte("synthetic\x00value"), nil, nil, false},
		{"internal lf", []byte("synthetic\nvalue"), nil, nil, false},
		{"quoted", []byte("'synthetic-value'"), nil, nil, false},
		{"boundary space", []byte(" synthetic-value"), nil, nil, false},
		{"read error", []byte("synthetic-hidden-value"), errors.New("synthetic-hidden-value"), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			console := &fakeOperatorConsole{inputs: [][]byte{tc.value}, readErr: tc.readErr}
			terminal := &OperatorTerminal{console: console, confirmed: true}
			defer terminal.Close()
			value, err := terminal.ReadValue()
			defer secure.Clear(value)
			assertClearedOperatorBytes(t, tc.value)
			if tc.valid {
				if err != nil || !bytes.Equal(value, []byte("synthetic-hidden-value")) {
					t.Fatal("hidden input ownership or normalization failed")
				}
			} else if err != secure.ErrInput || value != nil {
				t.Fatal("invalid hidden input escaped fixed error boundary")
			}
			if strings.Contains(console.String(), "synthetic-hidden-value") {
				t.Fatal("value echoed to terminal")
			}
		})
	}
}

func TestOperatorConsentInvalidationAndClose(t *testing.T) {
	request := syntheticOperatorRequest(t)
	answer, err := operatorChallenge(request)
	if err != nil {
		t.Fatal(err)
	}
	console := &fakeOperatorConsole{inputs: [][]byte{answer, []byte("no")}}
	terminal := &OperatorTerminal{console: console}
	if _, err := terminal.ReadValue(); err != secure.ErrConsent || console.reads != 0 {
		t.Fatal("read before consent")
	}
	if err := terminal.Confirm(request); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Confirm(request); err != secure.ErrConsent {
		t.Fatal("second confirmation did not decline")
	}
	if _, err := terminal.ReadValue(); err != secure.ErrConsent || console.reads != 2 {
		t.Fatal("decline retained earlier consent")
	}
	if err := terminal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := terminal.Close(); err != nil || console.closes != 1 || terminal.confirmed {
		t.Fatal("terminal cleanup is not idempotent")
	}
	if _, err := terminal.ReadValue(); err != secure.ErrConsent {
		t.Fatal("read after close")
	}
	if err := terminal.Confirm(request); err != secure.ErrTerminal {
		t.Fatal("confirm after close")
	}
	var zero OperatorTerminal
	if err := zero.Confirm(request); err != secure.ErrTerminal {
		t.Fatal("zero terminal confirms")
	}
	var absent *OperatorTerminal
	if err := absent.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorRejectsInvalidRequestsWithoutPrompt(t *testing.T) {
	for _, change := range []func(*OperatorRequest){
		func(r *OperatorRequest) { r.Action = "run" },
		func(r *OperatorRequest) { r.Target = "bare" },
		func(r *OperatorRequest) { r.Target = "file:relative" },
		func(r *OperatorRequest) { r.Target = "libsecret:bad/name" },
		func(r *OperatorRequest) { r.Target += "\nforged" },
		func(r *OperatorRequest) { r.Source = "op:fake\x1b[2J" },
		func(r *OperatorRequest) { r.Keys = nil },
		func(r *OperatorRequest) { r.Keys = []string{"BAD KEY"} },
		func(r *OperatorRequest) { r.Labels = map[string]string{"env": "bad value"} },
	} {
		request := syntheticOperatorRequest(t)
		change(&request)
		console := &fakeOperatorConsole{}
		terminal := &OperatorTerminal{console: console, confirmed: true}
		if err := terminal.Confirm(request); err != secure.ErrInvalidRequest || console.Len() != 0 || console.reads != 0 || terminal.confirmed {
			t.Fatal("invalid request prompted, retained consent or returned variable error")
		}
		_ = terminal.Close()
	}
}

func TestOperatorTerminalIOFailures(t *testing.T) {
	request := syntheticOperatorRequest(t)
	console := &fakeOperatorConsole{writeErr: errors.New("synthetic diagnostic")}
	terminal := &OperatorTerminal{console: console, confirmed: true}
	if _, err := terminal.ReadValue(); err != secure.ErrInput || console.reads != 0 {
		t.Fatal("value read after prompt failure")
	}
	if err := terminal.Confirm(request); err != secure.ErrTerminal || terminal.confirmed {
		t.Fatal("confirmation accepted after prompt failure")
	}
	console.closeErr = errors.New("synthetic diagnostic")
	if err := terminal.Close(); err != secure.ErrTerminal || console.closes != 1 {
		t.Fatal("close leaked terminal error")
	}
}
