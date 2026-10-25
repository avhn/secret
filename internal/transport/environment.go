package transport

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrWindowsEnvironment = errors.New("invalid Windows child environment")

// WindowsEnvironmentKey splits an environment entry, including the native =C:
// drive-current-directory form. No other name may contain '='.
func WindowsEnvironmentKey(entry string) (string, bool) {
	start := 0
	if strings.HasPrefix(entry, "=") {
		if len(entry) < 4 || entry[2] != ':' || entry[3] != '=' || !((entry[1] >= 'A' && entry[1] <= 'Z') || (entry[1] >= 'a' && entry[1] <= 'z')) {
			return "", false
		}
		start = 1
	}
	i := strings.IndexByte(entry[start:], '=')
	if i < 0 || i+start == 0 {
		return "", false
	}
	return entry[:i+start], true
}

// WindowsEnvironment constructs an explicit, sorted, double-NUL-terminated
// UTF-16 block. Invalid UTF-8, NUL and case-insensitive duplicate names fail
// before process creation: lossy conversion would defeat literal redaction.
// The caller owns the returned block and must clear it after CreateProcess.
// This helper is portable so the encoding contract is tested on every platform.
func WindowsEnvironment(env []string) ([]uint16, error) {
	type entry struct {
		text string
		key  []uint16
	}
	entries := make([]entry, 0, len(env))
	seen := make(map[string]bool, len(env))
	for _, text := range env {
		name, ok := WindowsEnvironmentKey(text)
		if !ok || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return nil, ErrWindowsEnvironment
		}
		key := strings.ToUpper(name)
		if seen[key] {
			return nil, ErrWindowsEnvironment
		}
		seen[key] = true
		entries = append(entries, entry{text, utf16.Encode([]rune(key))})
	}
	slices.SortFunc(entries, func(a, b entry) int { return slices.Compare(a.key, b.key) })
	block := make([]uint16, 0)
	for _, entry := range entries {
		for _, r := range entry.text {
			if r <= 0xffff {
				block = append(block, uint16(r))
			} else {
				hi, lo := utf16.EncodeRune(r)
				block = append(block, uint16(hi), uint16(lo))
			}
		}
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}
