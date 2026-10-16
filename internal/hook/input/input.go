// Package input validates bounded PreToolUse envelopes without interpreting command text.
package input

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
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
	if err != nil || len(data) > MaxBytes || len(bytes.TrimSpace(data)) == 0 || !utf8.Valid(data) {
		return Envelope{}, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := validate(d); err != nil {
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
	if !ok || tool == "" {
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
	if !exists || string(raw) == "null" {
		return "", true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || bad(value) || strings.ContainsAny(value, "\n\t") {
		return "", false
	}
	return value, true
}

// bad rejects controls which can change host path or shell parsing.
func bad(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' || r == 0x7f }) >= 0
}

// validate walks tokens recursively so json.Unmarshal cannot silently accept duplicate keys.
func validate(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if err := validate(d); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	case json.Delim('['):
		for d.More() {
			if err := validate(d); err != nil {
				return err
			}
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
