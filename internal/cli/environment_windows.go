//go:build windows

package cli

import (
	"strings"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/transport"
)

func environmentKey(key string) string { return strings.ToUpper(key) }
func environmentEntryKey(entry string) (string, bool) {
	return transport.WindowsEnvironmentKey(entry)
}
func validateEnvironmentSelection(selection store.Selection) error {
	seen := make(map[string]bool, len(selection.Keys))
	for _, key := range selection.Keys {
		folded := environmentKey(key)
		if seen[folded] {
			return transport.ErrWindowsEnvironment
		}
		seen[folded] = true
	}
	return nil
}
func validateChildEnvironment(env []string) error {
	block, err := transport.WindowsEnvironment(env)
	for i := range block {
		block[i] = 0
	}
	return err
}
