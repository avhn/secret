package secure

import (
	"bytes"
	"strings"
	"testing"
)

func TestCloneOwnership(t *testing.T) {
	for _, original := range [][]byte{nil, {}, []byte("synthetic-value"), {0, 255, 1}} {
		copy := Clone(original)
		if !bytes.Equal(copy, original) || (copy == nil) != (original == nil) {
			t.Fatal("clone changed bytes or nil ownership")
		}
		Clear(copy)
		if len(original) != 0 && bytes.Equal(copy, original) {
			t.Fatal("clone shares the original allocation")
		}
	}
}

func TestClearOwnedCapacity(t *testing.T) {
	owned := []byte("synthetic-value")
	shortened := owned[:3]
	Clear(shortened)
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("cleanup left bytes beyond length")
	}
	Clear(owned[:0])
	Clear(nil)
	Clear(owned)
}

func TestFixedErrors(t *testing.T) {
	seen := make(map[string]bool)
	for _, err := range []error{ErrTerminalRequired, ErrTerminal, ErrConsent, ErrInput, ErrInvalidRequest, ErrUnsupported, ErrTransaction, ErrConflict, ErrNotFound, ErrRecovery, ErrAudit} {
		text := err.Error()
		if !strings.Contains(text, "operator ") || strings.ContainsAny(text, "\r\n") || seen[text] {
			t.Fatal("operator error is not a distinct fixed category")
		}
		seen[text] = true
	}
}
