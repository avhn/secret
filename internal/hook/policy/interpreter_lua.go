package policy

import "strings"

// Lua long strings retain their bytes without escapes or interpolation. The
// delimiter's equals count must match; this scanner never evaluates source.
func luaLiteralToken(code string, start int) (interpreterToken, int, bool) {
	if start >= len(code) || code[start] != '[' {
		return interpreterToken{}, start, false
	}
	i := start + 1
	for i < len(code) && code[i] == '=' {
		i++
	}
	if i >= len(code) || code[i] != '[' {
		return interpreterToken{}, start, false
	}
	close := "]" + code[start+1:i] + "]"
	i++
	if end := strings.Index(code[i:], close); end >= 0 {
		return interpreterToken{text: code[i : i+end], literal: true, witness: true}, i + end + len(close), true
	}
	return interpreterToken{text: code[i:], indeterminate: true}, len(code), true
}
