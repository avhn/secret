package transport

import (
	"bytes"
	"io"
	"testing"
)

func TestChunkBoundaries(t *testing.T) {
	patterns := [][]byte{[]byte("abcdef"), []byte("abc"), []byte("bc"), []byte("x.y"), []byte{0xff, 0x00}, nil}
	input := []byte("abcabcdef|x.y|\xff\x00|ab")
	want := []byte("<redacted><redacted>|<redacted>|<redacted>|ab")
	m, e := NewMatcher(patterns)
	if e != nil {
		t.Fatal(e)
	}
	for split := 0; split <= len(input); split++ {
		var out bytes.Buffer
		if e = m.Filter(io.MultiReader(bytes.NewReader(input[:split]), bytes.NewReader(input[split:])), &out); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("split %d: %q", split, out.Bytes())
		}
	}
}

func FuzzRedaction(f *testing.F) {
	f.Add([]byte("synthetic-token|synthetic-token"))
	f.Add([]byte("synthetic-token"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 256 {
			t.Skip()
		}
		value := []byte("synthetic-token")
		m, e := NewMatcher([][]byte{value})
		if e != nil {
			t.Fatal(e)
		}
		for split := 0; split <= len(input); split++ {
			var out bytes.Buffer
			if e = m.Filter(io.MultiReader(bytes.NewReader(input[:split]), bytes.NewReader(input[split:])), &out); e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(out.Bytes(), value) {
				t.Fatalf("value in output at split %d", split)
			}
		}
	})
}

func TestPatternBound(t *testing.T) {
	_, e := NewMatcher([][]byte{bytes.Repeat([]byte{'a'}, maxPatterns+1)})
	if e == nil {
		t.Fatal("unbounded patterns accepted")
	}
}
