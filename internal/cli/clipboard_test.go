package cli

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/avhn/secret/internal/secure"
)

func TestClipboardSetupFailureCleanup(t *testing.T) {
	for _, tc := range []struct {
		name                string
		copyFail, setupFail bool
		changed, oversized  bool
		wantEvents          []string
		wantError           string
	}{
		{name: "success", wantEvents: []string{"copy", "start"}},
		{name: "copy-failed", copyFail: true, wantEvents: []string{"copy"}, wantError: "clipboard copy failed"},
		{name: "setup-failed-unchanged", setupFail: true, wantEvents: []string{"copy", "start", "clear"}, wantError: "clipboard clear setup failed"},
		{name: "setup-failed-changed", setupFail: true, changed: true, wantEvents: []string{"copy", "start", "clear"}, wantError: "clipboard clear setup failed"},
		{name: "oversized", oversized: true, wantError: "clipboard clear setup failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := []byte("synthetic")
			if tc.oversized {
				value = bytes.Repeat([]byte{'s'}, clipboardValueLimit+1)
			}
			defer secure.Clear(value)
			var events []string
			var current []byte
			defer func() { secure.Clear(current) }()
			copyError := errors.New("clipboard copy failed")
			setupError := errors.New("clipboard clear setup failed")
			actions := clipboardActions{
				copy: func(got []byte) error {
					events = append(events, "copy")
					if !bytes.Equal(got, value) {
						t.Fatal("copy received a different value")
					}
					if tc.copyFail {
						return copyError
					}
					current = bytes.Clone(got)
					return nil
				},
				startClear: func(got []byte, seconds int) error {
					events = append(events, "start")
					if !bytes.Equal(got, value) || seconds != 45 {
						t.Fatal("clearer setup received a different value or timeout")
					}
					if tc.changed {
						secure.Clear(current)
						current = []byte("synthetic-replacement")
					}
					if tc.setupFail {
						return setupError
					}
					return nil
				},
				clearIfUnchanged: func(got []byte) {
					events = append(events, "clear")
					if !bytes.Equal(got, value) {
						t.Fatal("failure cleanup received a different value")
					}
					if bytes.Equal(current, got) {
						secure.Clear(current)
						current = nil
					}
				},
			}
			err := actions.copyAndStartClear(value, 45)
			if (err != nil) != (tc.wantError != "") || err != nil && err.Error() != tc.wantError || !reflect.DeepEqual(events, tc.wantEvents) {
				t.Fatal("clipboard setup error or operation order mismatch")
			}
			if tc.setupFail && err != setupError {
				t.Fatal("cleanup replaced the original setup error")
			}
			if tc.setupFail && !tc.changed && len(current) != 0 {
				t.Fatal("setup failure left unchanged contents behind")
			}
			if tc.changed && !bytes.Equal(current, []byte("synthetic-replacement")) {
				t.Fatal("setup failure cleared replacement contents")
			}
		})
	}
}

type clipboardReadSpy struct {
	in     io.Reader
	buffer []byte
}

func (r *clipboardReadSpy) Read(p []byte) (int, error) {
	if r.buffer == nil {
		r.buffer = p[:cap(p)]
	}
	return r.in.Read(p)
}

type clipboardReadError struct{}

func (clipboardReadError) Read([]byte) (int, error) {
	return 0, errors.New("synthetic input failure")
}

func TestClipboardClearBoundedInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		failed bool
		status int
	}{
		{name: "empty"},
		{name: "small", size: 9},
		{name: "previous-growth-boundary", size: 4097},
		{name: "exact-limit", size: clipboardValueLimit},
		{name: "oversized", size: clipboardValueLimit + 1, status: 1},
		{name: "error-empty", failed: true, status: 1},
		{name: "error-partial", size: 4097, failed: true, status: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := bytes.Repeat([]byte{'s'}, tc.size)
			defer secure.Clear(value)
			var input io.Reader = bytes.NewReader(value)
			if tc.failed {
				input = io.MultiReader(input, clipboardReadError{})
			}
			spy := &clipboardReadSpy{in: input}
			called := false
			status := runClipboardClear(spy, 0, func(got []byte) {
				called = true
				if !bytes.Equal(got, value) {
					t.Fatal("clearer received a different value")
				}
			})
			if status != tc.status || called != (tc.status == 0) {
				t.Fatal("bounded clipboard input status mismatch")
			}
			if len(spy.buffer) != clipboardValueLimit+1 || bytes.Count(spy.buffer, []byte{0}) != len(spy.buffer) {
				t.Fatal("clipboard input allocation was not bounded and fully zeroed")
			}
		})
	}
}
