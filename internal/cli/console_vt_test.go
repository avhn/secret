package cli

import (
	"bytes"
	"testing"
)

// consoleVisibleText is a test oracle, not a terminal emulator. ConPTY can split
// printed tokens with cursor/style sequences or physical line wraps. Ignore VT
// controls (including OSC titles), CR and LF, but retain every printable byte.
// The caller supplies the whole captured prefix, so partial sequences are retried
// when the next chunk arrives. Never return a captured transcript on failure.
func consoleVisibleText(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] == '\x1b' {
			i++
			if i == len(data) {
				break
			}
			switch data[i] {
			case '[': // CSI: parameters/intermediates, then a final byte.
				for i++; i < len(data) && (data[i] < 0x40 || data[i] > 0x7e); i++ {
				}
			case ']', 'P', 'X', '^', '_': // OSC/DCS/SOS/PM/APC strings.
				for i++; i < len(data); i++ {
					if data[i] == '\a' {
						break
					}
					if data[i] == '\x1b' && i+1 < len(data) && data[i+1] == '\\' {
						i++
						break
					}
				}
			default: // Other ESC sequences have optional intermediate bytes.
				for i < len(data) && data[i] >= 0x20 && data[i] <= 0x2f {
					i++
				}
			}
			continue
		}
		if data[i] >= 0x20 && data[i] != 0x7f {
			out = append(out, data[i])
		}
	}
	return out
}

func TestConsoleVisibleText(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"plain", "WINDOWS_CONSOLE_OK", "WINDOWS_CONSOLE_OK"},
		{"cursor and wrap", "WINDOWS_\x1b[18CCONSOLE_\r\nOK\x1b[0m", "WINDOWS_CONSOLE_OK"},
		{"prompt blanks", "New value (hidden):\x1b[1C", "New value (hidden):"},
		{"title is not a witness", "\x1b]0;WINDOWS_CONSOLE_OK\aactual", "actual"},
		{"string terminator", "\x1bPignored\x1b\\actual", "actual"},
		{"charset and cursor", "\x1b(B\x1b7actual\x1b8", "actual"},
		{"partial CSI", "WINDOWS_\x1b[12", "WINDOWS_"},
		{"partial OSC", "\x1b]0;WINDOWS_CONSOLE_OK", ""},
		{"partial ESC", "actual\x1b", "actual"},
		{"hidden Unicode witness", "synthetic-\x1b[0mé-𐐷", "synthetic-é-𐐷"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !bytes.Equal(consoleVisibleText([]byte(test.input)), []byte(test.want)) {
				t.Fatal("console VT normalization changed printable text")
			}
		})
	}
	// Exercise every read boundary, including within UTF-8 and VT sequences.
	input := []byte("WINDOWS_\x1b[1CCONSOLE_\r\nOK")
	for split := 0; split <= len(input); split++ {
		prefix := append([]byte(nil), input[:split]...)
		_ = consoleVisibleText(prefix)
		prefix = append(prefix, input[split:]...)
		if !bytes.Equal(consoleVisibleText(prefix), []byte("WINDOWS_CONSOLE_OK")) {
			t.Fatal("console marker depended on pipe read boundary")
		}
	}
}
