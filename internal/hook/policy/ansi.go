package policy

import (
	"strconv"
	"strings"
)

// ansiLiteral decodes shell ANSI-C quoting without evaluating shell source.
// Match the retained guard's ASCII Unicode support and reserved separators;
// unknown escapes remain literal, rather than losing their backslash.
func ansiLiteral(value string) (string, bool) {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\\' {
			out.WriteByte(c)
			continue
		}
		i++
		if i >= len(value) {
			return "", false
		}
		c = value[i]
		switch c {
		case '\\', '\'', '"':
		case 'a':
			c = '\a'
		case 'b':
			c = '\b'
		case 'e', 'E':
			c = 27
		case 'f':
			c = '\f'
		case 'n':
			c = '\n'
		case 'r':
			c = '\r'
		case 't':
			c = '\t'
		case 'v':
			c = '\v'
		case 'c':
			i++
			if i >= len(value) {
				return "", false
			}
			c = value[i] & 31
		case 'x', 'u', 'U', '0', '1', '2', '3', '4', '5', '6', '7':
			base, limit, start := 16, 2, i+1
			if c >= '0' && c <= '7' {
				base, limit, start = 8, 3, i
			} else if c == 'u' {
				limit = 4
			} else if c == 'U' {
				limit = 8
			}
			end := start
			for end < len(value) && end-start < limit {
				digit := value[end]
				if !(digit >= '0' && digit <= '7' || base == 16 && (digit >= '8' && digit <= '9' || digit >= 'a' && digit <= 'f' || digit >= 'A' && digit <= 'F')) {
					break
				}
				end++
			}
			if c == 'u' || c == 'U' {
				if end-start != limit {
					return "", false
				}
			}
			if end == start {
				out.WriteByte('\\')
				out.WriteByte(c)
				continue
			}
			n, err := strconv.ParseUint(value[start:end], base, 32)
			if err != nil || (c == 'u' || c == 'U') && n > 127 {
				return "", false
			}
			c, i = byte(n), end-1
		default:
			out.WriteByte('\\')
		}
		if c == 0 || c >= 29 && c <= 31 {
			return "", false
		}
		out.WriteByte(c)
	}
	return out.String(), true
}
