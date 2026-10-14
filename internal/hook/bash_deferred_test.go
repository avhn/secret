//go:build !hooktrial

package hook

import (
	"bytes"
	"strings"
	"testing"
)

// TestBashDeferred checks that the installed hook remains responsible for shell calls.
func TestBashDeferred(t *testing.T) {
	var out bytes.Buffer
	if err := Decide("claude", strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`), &out); err != nil || out.Len() != 0 {
		t.Fatalf("deferred shell call: output=%q error=%v", out.String(), err)
	}
}
