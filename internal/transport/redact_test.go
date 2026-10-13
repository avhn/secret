package transport

import (
	"bytes"
	"io"
	"testing"
	"time"
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

// referenceFilter applies leftmost-longest replacement without streaming optimizations.
func referenceFilter(input []byte, patterns [][]byte) []byte {
	var out []byte
	for i := 0; i < len(input); {
		longest := 0
		for _, p := range patterns {
			if len(p) > longest && bytes.HasPrefix(input[i:], p) {
				longest = len(p)
			}
		}
		if longest > 0 {
			out = append(out, replacement...)
			i += longest
		} else {
			out = append(out, input[i])
			i++
		}
	}
	return out
}

func FuzzRedactionDifferential(f *testing.F) {
	f.Add([]byte("ababa"), []byte("aba"), []byte("ba"))
	f.Add([]byte{0, 1, 0, 1}, []byte{0, 1}, []byte{1, 0, 1})
	f.Fuzz(func(t *testing.T, input, a, b []byte) {
		if len(input) > 512 || len(a) > 64 || len(b) > 64 {
			t.Skip()
		}
		patterns := [][]byte{a, b, []byte("aba"), []byte("ab")}
		matcher, err := NewMatcher(patterns)
		if err != nil {
			t.Fatal(err)
		}
		want := referenceFilter(input, patterns)
		for split := 0; split <= len(input); split += 1 + len(input)/16 {
			var out bytes.Buffer
			err = matcher.Filter(io.MultiReader(bytes.NewReader(input[:split]), bytes.NewReader(input[split:])), &out)
			if err != nil || !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("split %d: got %q want %q err %v", split, out.Bytes(), want, err)
			}
		}
	})
}

func TestRepeatedPrefixStream(t *testing.T) {
	value := append(bytes.Repeat([]byte{'a'}, 1<<20), 'b')
	matcher, err := NewMatcher([][]byte{value})
	if err != nil {
		t.Fatal(err)
	}
	input := bytes.Repeat([]byte{'a'}, 3<<20)
	start := time.Now()
	var out bytes.Buffer
	if err := matcher.Filter(bytes.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), input) || time.Since(start) > 20*time.Second {
		t.Fatalf("repetitive stream failed after %s", time.Since(start))
	}
}
