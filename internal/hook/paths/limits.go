package paths

import (
	"path/filepath"
	"strings"
)

// RawWithinLimits matches the retained guard's UTF-8 byte limits before path
// cleaning or metadata lookup can hide redundant or oversized components.
// Native separators are recognized on Windows in addition to forward slashes.
func RawWithinLimits(name string) bool {
	if len(name) > 4096 {
		return false
	}
	for _, component := range strings.Split(filepath.ToSlash(name), "/") {
		if len(component) > 255 {
			return false
		}
	}
	return true
}
