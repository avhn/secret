// Package input validates bounded PreToolUse envelopes without interpreting command text.
package input

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"
)

var ErrInvalid = errors.New("invalid hook envelope")

// Envelope contains only fields required to classify a supported tool call.
type Envelope struct {
	Tool   string
	CWD    string
	Fields map[string]json.RawMessage
}

// Decode reads at most one JSON object, rejecting duplicate keys at every depth.
// An empty or malformed request is reported as ErrInvalid without echoing its content.
func Decode(r io.Reader) (Envelope, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(data) > MaxBytes || len(bytes.TrimSpace(data)) == 0 || !utf8.Valid(data) || !validSurrogates(data) {
		return Envelope{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	budget := validationBudget{}
	if err := budget.validate(d, 0); err != nil {
		return Envelope{}, ErrInvalid
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Envelope{}, ErrInvalid
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return Envelope{}, ErrInvalid
	}
	tool, ok := text(root, "tool_name")
	if !ok || strings.TrimSpace(tool) == "" {
		return Envelope{}, ErrInvalid
	}
	cwd, ok := text(root, "cwd")
	if !ok || tool == "Bash" && !filepath.IsAbs(cwd) {
		return Envelope{}, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if raw := root["tool_input"]; len(raw) == 0 || json.Unmarshal(raw, &fields) != nil || fields == nil {
		return Envelope{}, ErrInvalid
	}
	for _, key := range []string{"file_path", "notebook_path", "path", "glob", "type", "output_mode", "workdir", "pattern"} {
		if _, ok := text(fields, key); !ok {
			return Envelope{}, ErrInvalid
		}
	}
	// File tools need an actual target. NotebookEdit uses the authoritative
	// notebook_path field; an unrelated file_path cannot substitute for it.
	switch tool {
	case "Read", "Edit", "Write", "MultiEdit":
		if value, ok := text(fields, "file_path"); !ok || value == "" {
			return Envelope{}, ErrInvalid
		}
	case "NotebookEdit":
		if notebook, ok := text(fields, "notebook_path"); !ok || notebook == "" {
			return Envelope{}, ErrInvalid
		}
	}
	raw, exists := fields["command"]
	if (tool == "Bash" || tool == "apply_patch") && !exists {
		return Envelope{}, ErrInvalid
	}
	if exists {
		switch {
		case len(raw) > 0 && raw[0] == '"':
			var cmd string
			if json.Unmarshal(raw, &cmd) != nil || strings.ContainsRune(cmd, 0) {
				return Envelope{}, ErrInvalid
			}
		case len(raw) > 0 && raw[0] == '[':
			var argv []json.RawMessage
			if json.Unmarshal(raw, &argv) != nil || len(argv) == 0 {
				return Envelope{}, ErrInvalid
			}
			for _, rawArg := range argv {
				var arg string
				if len(rawArg) == 0 || rawArg[0] != '"' || json.Unmarshal(rawArg, &arg) != nil || strings.ContainsRune(arg, 0) {
					return Envelope{}, ErrInvalid
				}
			}
		default:
			return Envelope{}, ErrInvalid
		}
	}
	return Envelope{Tool: tool, CWD: cwd, Fields: fields}, nil
}

// String returns an optional validated string field.
func (e Envelope) String(key string) string {
	if key == "command" {
		var value string
		_ = json.Unmarshal(e.Fields[key], &value)
		return value
	}
	value, _ := text(e.Fields, key)
	return value
}

// text checks that an optional field is a string and excludes unsafe controls.
func text(fields map[string]json.RawMessage, key string) (string, bool) {
	raw, exists := fields[key]
	if !exists {
		return "", true
	}
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || bad(value) || strings.ContainsAny(value, "\n\t") {
		return "", false
	}
	// Bound path normalization before filepath.Clean can hide excessive redundant
	// components. Bash's deadline also denies these under-cap envelope paths.
	switch key {
	case "cwd", "file_path", "notebook_path", "path", "workdir":
		if strings.Count(value, "/") > MaxPathSeparators {
			return "", false
		}
	}
	return value, true
}

// bad rejects controls which can change host path or shell parsing.
func bad(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f }) >= 0
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject them
// before decoding so malformed keys and paths cannot acquire different names.
// Escaped backslashes are skipped, and actual U+FFFD remains valid text.
func validSurrogates(data []byte) bool {
	quoted := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value < 0xd800 || value > 0xdfff {
			continue
		}
		if value > 0xdbff || i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xdc00 || low > 0xdfff {
			return false
		}
		i += 6
	}
	return true
}

// validationBudget counts keys globally and includes JSON punctuation in the
// token count, matching the retained Bash envelope scanner rather than only
// the scalar/container tokens exposed by encoding/json.
type validationBudget struct {
	keys, tokens int
}

func (b *validationBudget) consume(n int) error {
	b.tokens += n
	if b.tokens > MaxTokens {
		return ErrInvalid
	}
	return nil
}

// validate rejects duplicate keys and structural overflows before unmarshaling.
func (b *validationBudget) validate(d *json.Decoder, depth int) error {
	if err := b.consume(1); err != nil {
		return err
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'), json.Delim('['):
		if depth >= MaxDepth {
			return ErrInvalid
		}
		object := token == json.Delim('{')
		seen := map[string]bool{}
		first := true
		for d.More() {
			if !first {
				if err := b.consume(1); err != nil { // comma
					return err
				}
			}
			first = false
			if object {
				b.keys++
				if b.keys > MaxKeys {
					return ErrInvalid
				}
				if err := b.consume(2); err != nil { // key and colon
					return err
				}
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return ErrInvalid
				}
				seen[name] = true
			}
			if err := b.validate(d, depth+1); err != nil {
				return err
			}
		}
		if err := b.consume(1); err != nil { // closing delimiter
			return err
		}
		_, err = d.Token()
		return err
	default:
		return nil
	}
}

// Deny renders the existing Bash guard's host-compatible, value-free denial.
func Deny(reason string, guidance bool) []byte {
	if guidance {
		reason += "; use secret show FILE for masked names, or secret run -f FILE -- CMD; never disguise a denied command"
	}
	output, _ := json.Marshal(struct {
		Hook struct {
			Event    string `json:"hookEventName"`
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}{Hook: struct {
		Event    string `json:"hookEventName"`
		Decision string `json:"permissionDecision"`
		Reason   string `json:"permissionDecisionReason"`
	}{"PreToolUse", "deny", reason}})
	return append(output, '\n')
}
