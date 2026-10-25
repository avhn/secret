//go:build windows

package hook

import "github.com/avhn/secret/internal/hook/input"

const windowsShellReason = "shell requests are unsupported on Windows"

// Native shell dialects are not Bash. Validated string and argv requests both
// deny without parsing, expanding or launching any command. Decode still owns
// malformed-envelope denial before this boundary.
func bashDecision(_ input.Envelope, _ string, _ func(string) bool) string {
	return windowsShellReason
}
