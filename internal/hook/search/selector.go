package search

import (
	"path"
	"strings"
)

// selectorWitness replaces wildcard fields with bounded representative text.
// This preserves literal prefixes and suffixes that define protected names.
func selectorWitness(pattern, star string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			out.WriteString(star)
		case '?':
			out.WriteByte('x')
		case '[':
			end := i + 1
			if end < len(pattern) && (pattern[end] == '!' || pattern[end] == '^') {
				end++
			}
			if end < len(pattern) && pattern[end] == ']' {
				end++
			}
			for end < len(pattern) && pattern[end] != ']' {
				end++
			}
			if end == len(pattern) {
				return "", false
			}
			class := pattern[i : end+1]
			found := false
			for _, r := range "xenv0123456789abcdefghijklmnopqrstuvwxyz._-" {
				match, err := path.Match(class, string(r))
				if err != nil {
					return "", false
				}
				if match {
					out.WriteRune(r)
					found = true
					break
				}
			}
			if !found {
				return "", false
			}
			i = end
		case '\\':
			i++
			if i == len(pattern) {
				return "", false
			}
			out.WriteByte(pattern[i])
		default:
			out.WriteByte(pattern[i])
		}
	}
	return out.String(), true
}
