package input

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestReadWithin(t *testing.T) {
	for _, tc := range []struct {
		name, source string
		invalid      bool
	}{
		{"empty", "", false}, {"ordinary", "synthetic", false},
		{"at cap", strings.Repeat("x", MaxBytes), false},
		{"over cap", strings.Repeat("x", MaxBytes+1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := Read(strings.NewReader(tc.source))
			if errors.Is(err, ErrInvalid) != tc.invalid || !tc.invalid && string(data) != tc.source {
				t.Errorf("bytes=%d err=%v want invalid=%v", len(data), err, tc.invalid)
			}
		})
	}
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	start := time.Now()
	if data, err := readWithin(r, 20*time.Millisecond); !errors.Is(err, ErrInvalid) || data != nil {
		t.Errorf("pending read: bytes=%d err=%v", len(data), err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("pending read took %s", elapsed)
	}
	// A late completion must release the reading goroutine without a receiver.
	if _, err := io.WriteString(w, "synthetic late input"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeReadDeadline(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	if _, err := Decode(r); !errors.Is(err, ErrInvalid) {
		t.Errorf("held-open Decode: %v", err)
	}
}
