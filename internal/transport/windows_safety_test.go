package transport

import (
	"bytes"
	"testing"
)

func TestWindowsSearchDirectory(t *testing.T) {
	for _, path := range []string{"", ".", "..", "bin", `..\bin`, `C:bin`, `\bin`, "/bin", `\\.\device`, `\\?\C:\bin`} {
		if WindowsSearchDirectory(path) {
			t.Fatalf("relative/ambiguous search directory accepted: %q", path)
		}
	}
	for _, path := range []string{`C:\bin`, "D:/bin", `\\server\share\bin`} {
		if !WindowsSearchDirectory(path) {
			t.Fatalf("absolute search directory refused: %q", path)
		}
	}
}

func TestWindowsMatcherEncodings(t *testing.T) {
	value := []byte("xé𐐷")
	le := []byte{'x', 0, 0xe9, 0, 1, 0xd8, 0x37, 0xdc}
	be := []byte{0, 'x', 0, 0xe9, 0xd8, 1, 0xdc, 0x37}
	matcher, err := NewWindowsMatcher([][]byte{value})
	if err != nil {
		t.Fatal(err)
	}
	for _, pattern := range [][]byte{value, le, be} {
		var output bytes.Buffer
		if err := matcher.Filter(bytes.NewReader(pattern), &output); err != nil || output.String() != "<redacted>" {
			t.Fatal("Windows encoding was not redacted")
		}
	}
	if !bytes.Equal(value, []byte("xé𐐷")) {
		t.Fatal("borrowed value changed")
	}
	raw, err := NewWindowsMatcher([][]byte{{0xff}})
	if err != nil {
		t.Fatal("unselected raw pattern rejected")
	}
	var rawOutput bytes.Buffer
	if err := raw.Filter(bytes.NewReader([]byte{0xff}), &rawOutput); err != nil || rawOutput.String() != "<redacted>" {
		t.Fatal("non-UTF-8 raw pattern lost")
	}
	if _, err := NewWindowsMatcher([][]byte{bytes.Repeat([]byte{'x'}, maxPatterns/5+1)}); err == nil {
		t.Fatal("expanded patterns exceeded aggregate bound")
	}
}
