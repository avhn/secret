package policy

import "strings"

// Find a JavaScript interpolation's closing brace without treating strings,
// comments, regex data or nested templates as expression framing. This only
// extracts executable source; the shared interpreter classifier decides roles.
// Recursive lexical work is bounded independently of classification depth.
func javascriptInterpolationEnd(code string, start, depth int, work *int) (int, bool) {
	if depth > 64 {
		return start, false
	}
	braces := 0
	var prior []interpreterToken
	for i := start; i < len(code); {
		*work++
		if *work > 1<<20 {
			return i, false
		}
		ch := code[i]
		if strings.ContainsRune(" \t\r\n", rune(ch)) {
			i++
			continue
		}
		if strings.HasPrefix(code[i:], "//") {
			end := strings.IndexByte(code[i:], '\n')
			if end < 0 {
				return i, false
			}
			i += end
			continue
		}
		if strings.HasPrefix(code[i:], "/*") {
			end := strings.Index(code[i+2:], "*/")
			if end < 0 {
				return i, false
			}
			i += end + 4
			continue
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			end, known := javascriptQuotedEnd(code, i, depth+1, work)
			if !known {
				return end, false
			}
			i = end
			prior = []interpreterToken{{literal: true}}
			continue
		}
		if ch == '/' && interpreterRegexStart(prior) {
			end, known := interpreterRegexEnd(code, i, work)
			if !known {
				return end, false
			}
			if end > i {
				i = end
				prior = []interpreterToken{{opaque: true}}
				continue
			}
		}
		if ch == '}' {
			if braces == 0 {
				return i, true
			}
			braces--
		} else if ch == '{' {
			braces++
			if braces+depth > 64 {
				return i, false
			}
		}
		begin := i
		i++
		if interpreterIdentifier(ch) {
			for i < len(code) && interpreterIdentifier(code[i]) {
				i++
			}
		}
		prior = []interpreterToken{{text: code[begin:i]}}
	}
	return len(code), false
}

func javascriptQuotedEnd(code string, start, depth int, work *int) (int, bool) {
	if depth > 64 {
		return start, false
	}
	quote := code[start]
	for i := start + 1; i < len(code); i++ {
		*work++
		if *work > 1<<20 {
			return i, false
		}
		if code[i] == '\\' {
			i++
		} else if code[i] == quote {
			return i + 1, true
		} else if quote == '`' && strings.HasPrefix(code[i:], "${") {
			end, known := javascriptInterpolationEnd(code, i+2, depth+1, work)
			if !known {
				return end, false
			}
			i = end
		}
	}
	return len(code), false
}
