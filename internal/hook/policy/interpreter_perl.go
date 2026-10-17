package policy

import "strings"

// Perl quote-like operators are atomic literals, including balanced paired
// delimiters. qx is shell source; qw supplies a literal list, not one argv word.
// Interpolation stays unknown, and no language expression is evaluated.
func perlLiteralTokens(code string, start int) ([]interpreterToken, int, bool) {
	if code[start] != 'q' || start > 0 && interpreterIdentifier(code[start-1]) {
		return nil, start, false
	}
	i := start + 1
	kind := "q"
	if i < len(code) && strings.ContainsRune("qwx", rune(code[i])) {
		kind += string(code[i])
		i++
	}
	for {
		delimiterStart := i
		for i < len(code) && strings.ContainsRune(" \t\r\n", rune(code[i])) {
			i++
		}
		// After whitespace, # begins a comment rather than a delimiter.
		// Find the real delimiter after it, keeping hashes inside the eventual
		// literal from becoming comments that could hide subsequent launches.
		if i < len(code) && i > delimiterStart && code[i] == '#' {
			if end := strings.IndexByte(code[i:], '\n'); end >= 0 {
				i += end
				continue
			}
			return nil, start, false
		}
		break
	}
	if i >= len(code) || interpreterIdentifier(code[i]) || code[i] == '\\' {
		return nil, start, false
	}
	// Fat-comma keys, single bare hash subscripts and method names are
	// autoquoted identifiers, not quote operators. Do not consume later code.
	prefix := strings.TrimSpace(code[:start])
	if strings.HasPrefix(code[i:], "=>") || strings.HasSuffix(prefix, "->") || strings.HasSuffix(prefix, "{") && code[i] == '}' {
		return nil, start, false
	}
	open, close := code[i], code[i]
	if index := strings.IndexByte("([{<", open); index >= 0 {
		close = ")]}>"[index]
	}
	i++
	depth := 1
	var value strings.Builder
	for i < len(code) {
		ch := code[i]
		i++
		if ch == '\\' && i < len(code) {
			next := code[i]
			i++
			if next == open || next == close || next == '\\' {
				value.WriteByte(next)
			} else {
				value.WriteByte(ch)
				value.WriteByte(next)
			}
			continue
		}
		if ch == close {
			depth--
			if depth == 0 {
				text := value.String()
				known := kind == "q" || kind == "qw" || !strings.ContainsAny(text, "$@")
				if kind == "qw" {
					var tokens []interpreterToken
					for _, word := range strings.Fields(text) {
						if len(tokens) > 0 {
							tokens = append(tokens, interpreterToken{text: ","})
						}
						tokens = append(tokens, interpreterToken{text: word, literal: true})
					}
					return tokens, i, true
				}
				return []interpreterToken{{text: text, literal: known, witness: true, shell: kind == "qx"}}, i, true
			}
		} else if open != close && ch == open {
			depth++
		}
		value.WriteByte(ch)
	}
	return []interpreterToken{{text: value.String(), indeterminate: true}}, i, true
}
