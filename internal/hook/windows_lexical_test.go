//go:build windows

package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// The policy corpus classifies only these exact Unix physical-traversal variants
// on Windows. Every one must still deny through Decide for both supported hosts,
// without executing Bash or relying on a native file traversal expectation.
func TestWindowsLexicalTraversalShellVariantsDeny(t *testing.T) {
	_, work := windowsHookFixture(t)
	data, err := os.ReadFile("../../testdata/hook/windows-lexical-variants.json")
	if err != nil {
		t.Fatal(err)
	}
	var variants []struct {
		Name    string `json:"case"`
		Variant int    `json:"variant"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(data, &variants); err != nil {
		t.Fatal(err)
	}
	if len(variants) != 8 {
		t.Fatalf("Windows lexical boundary has %d variants, want exactly 8", len(variants))
	}
	for _, variant := range variants {
		t.Run(fmt.Sprintf("%s/variant-%d", variant.Name, variant.Variant), func(t *testing.T) {
			// windowsHookCheck invokes Decide with a Bash envelope independently
			// for claude and codex, checking the exact fixed all-shell denial.
			windowsHookCheck(t, "Bash", work, map[string]any{"command": variant.Command}, windowsShellReason)
		})
	}
}
