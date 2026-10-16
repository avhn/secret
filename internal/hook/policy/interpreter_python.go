package policy

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Python prefixes belong to the following literal, not to a separate identifier.
// Only static strings supply argv witnesses; replacement fields and unsupported
// named Unicode escapes remain unknown. This never evaluates Python source.
func pythonLiteralToken(code string, start int) (interpreterToken, int, bool) {
	i := start
	for i < len(code) && (code[i] >= 'a' && code[i] <= 'z' || code[i] >= 'A' && code[i] <= 'Z') {
		i++
	}
	prefix := strings.ToLower(code[start:i])
	if prefix != "" && !optionIn("r u b f br rb fr rf", prefix) || i >= len(code) || code[i] != '\'' && code[i] != '"' {
		return interpreterToken{}, start, false
	}
	quote := code[i]
	delimiter := string(quote)
	if strings.HasPrefix(code[i:], strings.Repeat(delimiter, 3)) {
		delimiter = strings.Repeat(delimiter, 3)
	}
	i += len(delimiter)
	raw, bytes, formatted := strings.Contains(prefix, "r"), strings.Contains(prefix, "b"), strings.Contains(prefix, "f")
	known := start == 0 || !interpreterIdentifier(code[start-1])
	var value strings.Builder
	for i < len(code) {
		if strings.HasPrefix(code[i:], delimiter) {
			return interpreterToken{text: value.String(), literal: known}, i + len(delimiter), true
		}
		ch := code[i]
		if ch == '\\' && i+1 < len(code) {
			if formatted && (code[i+1] == '{' || code[i+1] == '}') {
				// A backslash does not escape a formatted replacement field.
				value.WriteByte(ch)
				i++
				continue
			}
			if raw {
				// Raw strings retain both the slash and any escaped quote.
				value.WriteString(code[i : i+2])
				i += 2
			} else {
				decoded, count, ok := pythonLiteralEscape(code[i:], bytes)
				value.WriteString(decoded)
				i += count
				known = known && ok
			}
			continue
		}
		if formatted && (ch == '{' || ch == '}') {
			if i+1 < len(code) && code[i+1] == ch {
				i++ // Doubled braces are literal braces, not replacement fields.
			} else {
				known = false
			}
		}
		if len(delimiter) == 1 && (ch == '\n' || ch == '\r') || bytes && ch >= utf8.RuneSelf {
			known = false
		}
		value.WriteByte(ch)
		i++
	}
	return interpreterToken{text: value.String()}, i, true
}

// Escape rules differ from Go: Python permits escaped opposite quotes, one to
// three octal digits, line continuations and unknown escapes retained verbatim.
// Bytes literals decode byte escapes but retain Unicode escape spellings.
func pythonLiteralEscape(source string, bytes bool) (string, int, bool) {
	ch := source[1]
	switch ch {
	case '\\', '\'', '"':
		return string(ch), 2, true
	case '\n':
		return "", 2, true
	case '\r':
		if len(source) > 2 && source[2] == '\n' {
			return "", 3, true
		}
		return "", 2, true
	}
	if index := strings.IndexByte("abfnrtv", ch); index >= 0 {
		return string("\a\b\f\n\r\t\v"[index]), 2, true
	}
	if ch >= '0' && ch <= '7' {
		end := 2
		for end < len(source) && end < 4 && source[end] >= '0' && source[end] <= '7' {
			end++
		}
		number, _ := strconv.ParseUint(source[1:end], 8, 32)
		if bytes {
			return string([]byte{byte(number)}), end, true
		}
		return string(rune(number)), end, true
	}
	digits := 0
	switch ch {
	case 'x':
		digits = 2
	case 'u':
		if !bytes {
			digits = 4
		}
	case 'U':
		if !bytes {
			digits = 8
		}
	case 'N':
		if !bytes {
			return source[:2], 2, false
		}
	}
	if digits == 0 {
		return source[:2], 2, true
	}
	end := 2 + digits
	if end > len(source) {
		return source[:2], 2, false
	}
	number, err := strconv.ParseUint(source[2:end], 16, 32)
	if err != nil || !utf8.ValidRune(rune(number)) {
		return source[:2], 2, false
	}
	if bytes {
		return string([]byte{byte(number)}), end, true
	}
	return string(rune(number)), end, true
}
