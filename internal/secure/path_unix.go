//go:build !windows

package secure

import (
	"os"
	"strings"
)

// UserHome preserves the existing Unix HOME contract, including an unset HOME.
func UserHome() (string, error) { return os.Getenv("HOME"), nil }

// ValidateStorePath leaves Unix filenames and byte behavior unchanged.
func ValidateStorePath(string) error { return nil }

// ExplicitStorePath preserves Bash-compatible slash-based path recognition.
func ExplicitStorePath(name string) bool { return strings.Contains(name, "/") }
