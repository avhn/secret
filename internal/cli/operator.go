package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"golang.org/x/term"
)

// OperatorRequest describes the exact names the human must confirm. Target must
// be an explicit absolute file: reference or implemented keystore reference.
// Source is optional names-only import/export provenance, validated by feature
// preflight. Keys includes both old and new keys for rename and every selected
// key for a batch. Labels are explicit selectors or exact identity labels. No
// values, command arguments or provider diagnostics may enter these fields.
type OperatorRequest struct {
	Action store.OperatorAction
	Source string
	Target string
	Keys   []string
	Labels map[string]string
}

// OperatorTerminal owns a controlling-terminal handle and a consent state. Its
// zero value cannot confirm or read values. It is synchronous, not goroutine-safe,
// and must be Closed on every path. A TTY is a UX check, not proof of identity;
// the unchanged hook denial remains the agent-side boundary.
type OperatorTerminal struct {
	console   operatorConsole
	confirmed bool
}

type operatorConsole interface {
	io.Writer
	io.Closer
	readPassword(prompt string, limit int) ([]byte, error)
}

const operatorValueLimit = 64 << 10

type controllingConsole struct{ *os.File }

func (console controllingConsole) readPassword(prompt string, limit int) (value []byte, err error) {
	state, err := term.MakeRaw(int(console.Fd()))
	if err != nil {
		return nil, secure.ErrTerminal
	}
	defer func() {
		if term.Restore(int(console.Fd()), state) != nil {
			err = secure.ErrTerminal
		}
		if err != nil {
			secure.Clear(value)
			value = nil
		}
	}()
	// Disable canonical buffering before displaying the prompt: even a pasted
	// line must not pass through the kernel's silently truncating line buffer.
	// Raw mode also disables output translation, so render prompt line endings.
	if _, err := io.WriteString(console, strings.ReplaceAll(prompt, "\n", "\r\n")); err != nil {
		return nil, secure.ErrTerminal
	}
	return readOperatorLine(console.File, limit)
}

// readOperatorLine owns a fixed buffer rather than reallocating secret prefixes.
// Overflow is sticky and drains through the line ending while input stays hidden,
// so a rejected suffix cannot spill into the next prompt or be echoed on restore.
func readOperatorLine(reader io.Reader, limit int) ([]byte, error) {
	if limit <= 0 || limit > operatorValueLimit {
		return nil, secure.ErrInput
	}
	buffer := make([]byte, limit)
	var input [1]byte
	success := false
	defer func() {
		secure.Clear(input[:])
		if !success {
			secure.Clear(buffer)
		}
	}()
	n, overflow := 0, false
	for {
		if _, err := io.ReadFull(reader, input[:]); err != nil {
			return nil, secure.ErrInput
		}
		switch input[0] {
		case '\r', '\n':
			if overflow {
				return nil, secure.ErrInput
			}
			success = true
			return buffer[:n], nil
		case 3, 4, 26, 28: // Raw-mode interrupt, EOF, suspend and quit cancel input.
			return nil, secure.ErrInput
		case '\b', 127:
			if n > 0 {
				n--
				buffer[n] = 0
			}
		case 21: // Preserve the usual hidden-input line erase (Ctrl-U).
			clear(buffer[:n])
			n = 0
		default:
			if n == limit {
				overflow = true
			} else if !overflow {
				buffer[n] = input[0]
				n++
			}
		}
	}
}

type operatorTerminalOps struct {
	isTerminal func(*os.File) bool
	open       func() (operatorConsole, error)
}

// RequireOperatorTerminal checks stdin AND stdout before opening the controlling
// terminal. Call it before resolving, statting, opening or listing any store, or
// invoking a provider. After this gate, callers may discover names-only metadata
// to construct a request, but must Confirm before fetching/moving values or
// mutating anything. There are no bypass flags, piped confirmations or JSON mode.
// Windows rejects before terminal opening or other side effects until M5a.
func RequireOperatorTerminal(in *os.File, out io.Writer) (*OperatorTerminal, error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	return requireOperatorTerminal(in, out, operatorTerminalOps{
		isTerminal: func(file *os.File) bool { return term.IsTerminal(int(file.Fd())) },
		open: func() (operatorConsole, error) {
			file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return nil, secure.ErrTerminal
			}
			if !term.IsTerminal(int(file.Fd())) {
				_ = file.Close()
				return nil, secure.ErrTerminal
			}
			return controllingConsole{file}, nil
		},
	})
}

func requireOperatorTerminal(in *os.File, out io.Writer, ops operatorTerminalOps) (*OperatorTerminal, error) {
	stdout, ok := out.(*os.File)
	if in == nil || !ok || stdout == nil || !ops.isTerminal(in) || !ops.isTerminal(stdout) {
		return nil, secure.ErrTerminalRequired
	}
	console, err := ops.open()
	if err != nil {
		if console != nil {
			_ = console.Close()
		}
		return nil, secure.ErrTerminal
	}
	if console == nil {
		return nil, secure.ErrTerminal
	}
	return &OperatorTerminal{console: console}, nil
}

// WithOperatorConsent is the simple boundary for requests whose names are already
// known without store access. It gates terminals and exact confirmation before
// calling work, and closes the terminal on every return. work may call ReadValue
// for rotation; it must return names-only errors and clear its owned value bytes.
// Requests requiring metadata discovery use RequireOperatorTerminal, then Confirm.
func WithOperatorConsent(in *os.File, out io.Writer, request OperatorRequest, work func(*OperatorTerminal) error) error {
	terminal, err := RequireOperatorTerminal(in, out)
	if err != nil {
		return err
	}
	defer terminal.Close()
	return terminal.withConsent(request, work)
}

func (terminal *OperatorTerminal) withConsent(request OperatorRequest, work func(*OperatorTerminal) error) error {
	if err := terminal.Confirm(request); err != nil {
		return err
	}
	if work == nil {
		return secure.ErrInvalidRequest
	}
	return work(terminal)
}

func safeOperatorName(name string) bool {
	if name == "" || len(name) > 4096 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

func operatorChallenge(request OperatorRequest) ([]byte, error) {
	if request.Action == store.ActionRegister || !request.Action.Valid() || !safeOperatorName(request.Target) || len(request.Keys) == 0 || len(request.Keys) > 1024 || (request.Source != "" && !safeOperatorName(request.Source)) {
		return nil, secure.ErrInvalidRequest
	}
	if strings.HasPrefix(request.Target, "file:") {
		if !filepath.IsAbs(strings.TrimPrefix(request.Target, "file:")) {
			return nil, secure.ErrInvalidRequest
		}
	} else if providerRef(request.Target) {
		if _, err := (store.Locator{}).Resolve(request.Target); err != nil {
			return nil, secure.ErrInvalidRequest
		}
	} else {
		return nil, secure.ErrInvalidRequest
	}
	if len(request.Labels) > 128 || store.ValidateIdentity(request.Keys[0], request.Labels) != nil {
		return nil, secure.ErrInvalidRequest
	}
	for _, key := range request.Keys {
		if len(key) > 256 || store.ValidateIdentity(key, nil) != nil {
			return nil, secure.ErrInvalidRequest
		}
	}
	challenge := string(request.Action) + " " + request.Target + " keys=" + strings.Join(request.Keys, ",")
	if request.Source != "" {
		challenge += " from=" + request.Source
	}
	if len(request.Labels) != 0 {
		challenge += " labels=" + store.CanonicalLabels(request.Labels)
	}
	if len(challenge) > 16384 {
		return nil, secure.ErrInvalidRequest
	}
	return []byte(challenge), nil
}

// Confirm requires the exact action, target, key list, source and canonical labels
// shown on the controlling terminal, not a generic yes. Confirmation input is
// hidden and never read from the command's stdin. It resets any previous consent
// even on failure. Callers must not reuse consent for a different request.
func (terminal *OperatorTerminal) Confirm(request OperatorRequest) error {
	if terminal == nil {
		return secure.ErrTerminal
	}
	terminal.confirmed = false
	if terminal.console == nil {
		return secure.ErrTerminal
	}
	challenge, err := operatorChallenge(request)
	if err != nil {
		return err
	}
	defer secure.Clear(challenge)
	prompt := fmt.Sprintf("Type exactly to confirm (input hidden):\n%s\n> ", challenge)
	answer, readErr := terminal.console.readPassword(prompt, len(challenge))
	defer secure.Clear(answer)
	_, writeErr := io.WriteString(terminal.console, "\n")
	if readErr == secure.ErrTerminal {
		return secure.ErrTerminal
	}
	if readErr != nil || writeErr != nil || !bytes.Equal(answer, challenge) {
		return secure.ErrConsent
	}
	terminal.confirmed = true
	return nil
}

// ReadValue obtains hidden rotation input only after successful Confirm. It
// normalizes with the existing stash grammar, clears raw input on every path and
// returns independently owned bytes that the caller must secure.Clear. Input is
// bounded to 64 KiB, with overflow rejected rather than truncated. It is never
// converted to a string, echoed, serialized or included in an error.
func (terminal *OperatorTerminal) ReadValue() ([]byte, error) {
	if terminal == nil || terminal.console == nil || !terminal.confirmed {
		return nil, secure.ErrConsent
	}
	value, readErr := terminal.console.readPassword("New value (hidden): ", operatorValueLimit)
	defer secure.Clear(value)
	_, writeErr := io.WriteString(terminal.console, "\n")
	if readErr != nil || writeErr != nil {
		return nil, secure.ErrInput
	}
	normalized, err := store.NormalizeValue(value)
	if err != nil {
		return nil, secure.ErrInput
	}
	return normalized, nil
}

// Close invalidates consent and releases only the owned terminal handle. It is
// idempotent; it never closes the command's stdin or stdout.
func (terminal *OperatorTerminal) Close() error {
	if terminal == nil {
		return nil
	}
	terminal.confirmed = false
	if terminal.console == nil {
		return nil
	}
	console := terminal.console
	terminal.console = nil
	if console.Close() != nil {
		return secure.ErrTerminal
	}
	return nil
}
