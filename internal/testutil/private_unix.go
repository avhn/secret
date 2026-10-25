//go:build !windows

// Package testutil creates synthetic private fixtures, never real stores.
package testutil

import (
	"os"
	"testing"
)

func TempDir(t testing.TB) string                  { t.Helper(); return t.TempDir() }
func Mkdir(path string, mode os.FileMode) error    { return os.Mkdir(path, mode) }
func MkdirAll(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
func WriteFile(path string, data []byte, mode os.FileMode) error {
	return os.WriteFile(path, data, mode)
}
