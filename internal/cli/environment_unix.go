//go:build !windows

package cli

import (
	"strings"

	"github.com/avhn/secret/internal/store"
)

func environmentKey(key string) string { return key }
func environmentEntryKey(entry string) (string, bool) {
	key, _, ok := strings.Cut(entry, "=")
	return key, ok
}
func validateEnvironmentSelection(store.Selection) error { return nil }
func validateChildEnvironment([]string) error            { return nil }
