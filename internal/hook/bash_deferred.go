//go:build !hooktrial

package hook

import "github.com/avhn/secret/internal/hook/input"

// bashDecision defers shell calls until the trial policy has been reviewed.
func bashDecision(input.Envelope, string, func(string) bool) string { return "" }
