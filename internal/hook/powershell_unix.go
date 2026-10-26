//go:build !windows

package hook

import "github.com/avhn/secret/internal/hook/input"

// PowerShell is not enabled on Unix or WSL, even through the test adapter.
func powershellDecision(_ string, _ input.Envelope, _, _ string) string {
	return powershellReason
}

// Preserve Unix behavior for unknown tools without guessing shell syntax.
func unknownShellDecision(_ input.Envelope) string { return "" }
