// Package patch checks Codex patch headers without reading or applying patch bodies.
package patch

import (
	"os"
	"strings"
	"unicode"

	"github.com/avhn/secret/internal/hook/paths"
)

const maxBytes = 40 << 10

const (
	protectedReason = "patch targets a protected store"
	invalidReason   = "command too complex to analyse for secret access; split it or use secret run"
)

// Decision classifies every source and destination header before accepting a patch.
// Malformed or ambiguous syntax cannot certify a safe patch.
func Decision(text, cwd, workdir, home string) string {
	if len(text) > maxBytes {
		return invalidReason
	}
	lines := strings.Split(text, "\n")
	started, ended, section, moved, invalid := false, false, false, false, false
	kind := ""
	for i, line := range lines {
		if strings.HasSuffix(line, "\r") {
			line = strings.TrimSuffix(line, "\r")
		}
		if strings.ContainsAny(line, "\r\x00") {
			// Malformed header bytes take precedence over filesystem checks on
			// every OS, including Windows path resolution failures.
			return invalidReason
		}
		if strings.HasPrefix(strings.TrimSpace(line), "***") {
			line = strings.TrimLeftFunc(line, unicode.IsSpace)
		}
		switch {
		case line == "*** Begin Patch":
			if i != 0 || started {
				invalid = true
			}
			started = true
		case line == "*** End Patch":
			if !started || ended || !section {
				invalid = true
			}
			ended = true
		case strings.HasPrefix(line, "*** Add File: "), strings.HasPrefix(line, "*** Update File: "), strings.HasPrefix(line, "*** Delete File: "), strings.HasPrefix(line, "*** Move to: "):
			prefix := line[:strings.Index(line, ": ")+2]
			name := strings.TrimPrefix(line, prefix)
			if name != "" && (paths.Protected(name, cwd, workdir, home) || paths.ConfigWriteProtected(name, cwd, workdir, home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("GIT_CONFIG_GLOBAL"))) {
				return protectedReason
			}
			if !started || ended || name == "" || strings.TrimSpace(name) != name || strings.ContainsAny(name, "\t\r\x00") {
				invalid = true
			}
			if prefix == "*** Move to: " {
				if kind != "*** Update File: " || moved {
					invalid = true
				}
				moved = true
			} else {
				kind = prefix
				section = true
				moved = false
			}
		case strings.HasPrefix(line, "***"):
			invalid = true
		default:
			// One final newline after End Patch is harmless.
			if !started || !section || ended && !(i == len(lines)-1 && line == "") {
				invalid = true
			}
		}
	}
	if invalid || !started || !ended || !section {
		return invalidReason
	}
	return ""
}
