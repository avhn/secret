// Package patch validates bounded Codex patch grammar without applying patches.
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

// Decision classifies every source and destination header before accepting a
// patch. Bodies are checked only for grammar, never applied, opened or echoed.
func Decision(text, cwd, workdir, home string) string {
	if len(text) > maxBytes || !paths.RawWithinLimits(cwd) || !paths.RawWithinLimits(workdir) || !paths.ValidPath(cwd) || !paths.ValidPath(workdir) {
		return invalidReason
	}
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		// Do not silently strip CR from native patch headers. All C0 and DEL
		// header bytes deny, including leading whitespace and path suffixes.
		header := strings.TrimLeftFunc(line, unicode.IsSpace)
		if strings.ContainsAny(line, "\r\x00") || (strings.HasPrefix(header, "***") || strings.HasPrefix(header, "@@")) && headerControls(line) {
			return invalidReason
		}
		// Validate every raw target before an earlier protected header can
		// short-circuit metadata classification with a different denial reason.
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(header, prefix) {
				name := strings.TrimPrefix(header, prefix)
				if !paths.RawWithinLimits(name) || !paths.ValidPath(name) {
					return invalidReason
				}
			}
		}
	}
	// Retain the conservative path-role backstop for header-looking lines even
	// when an upstream Update parser could read indentation as context data.
	for _, raw := range lines {
		line := strings.TrimLeftFunc(raw, unicode.IsSpace)
		for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
			if strings.HasPrefix(line, prefix) {
				name := strings.TrimPrefix(line, prefix)
				if name != "" && (paths.FileProtected(name, cwd, workdir, home) || paths.ConfigWriteProtected(name, cwd, workdir, home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("GIT_CONFIG_GLOBAL"))) {
					return protectedReason
				}
			}
		}
	}
	// Codex's lenient mode accepts these literal wrappers. They are framing,
	// not shell syntax: never expand or execute their contents. Require an exact
	// closing delimiter rather than upstream's ambiguous ends_with("EOF").
	wrapped := lines
	if len(wrapped) > 0 && wrapped[len(wrapped)-1] == "" {
		wrapped = wrapped[:len(wrapped)-1]
	}
	if len(wrapped) >= 4 && (wrapped[0] == "<<EOF" || wrapped[0] == "<<'EOF'" || wrapped[0] == "<<\"EOF\"") && wrapped[len(wrapped)-1] == "EOF" {
		lines = wrapped[1 : len(wrapped)-1]
	}
	last := len(lines) - 1
	if last >= 0 && lines[last] == "" {
		last--
	}
	started, ended, section, moved, invalid := false, false, false, false, false
	kind := ""
	hunk, hunkLines, eof := false, false, false
	finishSection := func() {
		if kind == "*** Update File: " && (!hunk || !hunkLines) {
			invalid = true
		}
	}
	for i, raw := range lines {
		line := raw
		trimmed := strings.TrimSpace(raw)
		if (trimmed == "*** Begin Patch" || trimmed == "*** End Patch") && (kind != "*** Update File: " || strings.HasPrefix(raw, "***") || i == last) {
			line = trimmed
		} else if kind != "*** Update File: " && strings.HasPrefix(trimmed, "***") {
			line = strings.TrimLeftFunc(raw, unicode.IsSpace)
		}
		// Upstream ignores empty/whitespace-only lines after an EOF marker.
		// Nonempty chunks still cannot restart after this retained terminator.
		if eof && !ended && trimmed == "" {
			continue
		}
		switch {
		case line == "*** Begin Patch":
			if i != 0 || started {
				invalid = true
			}
			started = true
		case line == "*** End Patch":
			finishSection()
			if !started || ended || !section {
				invalid = true
			}
			ended = true
		case strings.HasPrefix(line, "*** Add File: "), strings.HasPrefix(line, "*** Update File: "), strings.HasPrefix(line, "*** Delete File: "), strings.HasPrefix(line, "*** Move to: "):
			prefix := line[:strings.Index(line, ": ")+2]
			name := strings.TrimPrefix(line, prefix)
			if !paths.RawWithinLimits(name) {
				return invalidReason
			}
			if !started || ended || name == "" || strings.TrimSpace(name) != name {
				invalid = true
			}
			if prefix == "*** Move to: " {
				if kind != "*** Update File: " || moved || hunk || eof {
					invalid = true
				}
				moved = true
			} else {
				finishSection()
				kind, section, moved = prefix, true, false
				hunk, hunkLines, eof = false, false, false
			}
		case line == "*** End of File":
			if !started || ended || kind != "*** Update File: " || !hunk || !hunkLines || eof {
				invalid = true
			}
			eof = true
		case strings.HasPrefix(line, "***"):
			invalid = true
		default:
			// Exactly one final newline after End Patch is harmless.
			if ended && i == len(lines)-1 && line == "" {
				continue
			}
			if !started || !section || ended || eof {
				invalid = true
			}
			switch kind {
			case "*** Add File: ":
				if !strings.HasPrefix(line, "+") {
					invalid = true
				}
			case "*** Update File: ":
				if strings.TrimRightFunc(line, unicode.IsSpace) == "@@" || strings.HasPrefix(line, "@@ ") {
					if hunk && !hunkLines {
						invalid = true
					}
					hunk, hunkLines = true, false
				} else if line == "" || len(line) > 0 && strings.ContainsRune("+- ", rune(line[0])) {
					// The first chunk may omit @@; an unprefixed empty line is
					// empty context, matching Codex's streaming parser.
					hunk, hunkLines = true, true
				} else {
					invalid = true
				}
			default: // Delete sections cannot contain body lines.
				invalid = true
			}
		}
	}
	if invalid || !started || !ended || !section {
		return invalidReason
	}
	return ""
}

func headerControls(line string) bool {
	for i := 0; i < len(line); i++ {
		if line[i] < 0x20 || line[i] == 0x7f {
			return true
		}
	}
	return false
}
