//go:build windows

package cli

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsConsoleRecordUnit(t *testing.T) {
	const key = 1
	for _, tc := range []struct {
		name   string
		record consoleInputRecord
		unit   uint16
		repeat uint16
		ok     bool
	}{
		{"key down", consoleInputRecord{kind: key, down: 1, repeat: 1, key: 'A', char: 'a'}, 'a', 0, true},
		{"key down repeat", consoleInputRecord{kind: key, down: 1, repeat: 3, key: 'A', char: 'a'}, 'a', 2, true},
		{"key down zero repeat", consoleInputRecord{kind: key, down: 1, repeat: 0, key: 'A', char: 'a'}, 0, 0, false},
		{"ordinary key up", consoleInputRecord{kind: key, down: 0, repeat: 1, key: 'A', char: 'a'}, 0, 0, false},
		{"alt numpad composed", consoleInputRecord{kind: key, down: 0, repeat: 1, key: windows.VK_MENU, char: 0xe9}, 0xe9, 0, true},
		{"alt numpad high surrogate", consoleInputRecord{kind: key, down: 0, repeat: 0, key: windows.VK_MENU, char: 0xd801}, 0xd801, 0, true},
		{"plain alt release", consoleInputRecord{kind: key, down: 0, repeat: 1, key: windows.VK_MENU}, 0, 0, false},
		{"numpad digit under alt", consoleInputRecord{kind: key, down: 1, repeat: 1, key: windows.VK_NUMPAD2}, 0, 0, false},
		{"non-key event", consoleInputRecord{kind: 2, down: 1, repeat: 1, char: 'a'}, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unit, repeat, ok := recordUnit(&tc.record)
			if unit != tc.unit || repeat != tc.repeat || ok != tc.ok {
				t.Fatalf("got (%#x, %d, %v), want (%#x, %d, %v)", unit, repeat, ok, tc.unit, tc.repeat, tc.ok)
			}
		})
	}
}
