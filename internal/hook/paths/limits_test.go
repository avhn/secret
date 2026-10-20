package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRawWithinLimits(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		within     bool
	}{
		{"empty", "", true},
		{"component cap", strings.Repeat("a", 255), true},
		{"component overflow", strings.Repeat("a", 256), false},
		{"unicode cap", strings.Repeat("界", 85), true},
		{"unicode overflow", strings.Repeat("界", 86), false},
		{"path cap", strings.Repeat("a/", 2047) + "ab", true},
		{"path overflow", strings.Repeat("a/", 2048) + "a", false},
		{"raw redundant", strings.Repeat("./", 2049), false},
		{"raw dotdot", strings.Repeat("a", 256) + "/../public", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range []string{tc.path, filepath.FromSlash(tc.path)} {
				if got := RawWithinLimits(value); got != tc.within {
					t.Errorf("within=%v want %v", got, tc.within)
				}
			}
		})
	}
}
