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
	for i < len(code) && strings.ContainsRune(" \t\r\n", rune(code[i])) {
		i++
	}
	if i >= len(code) || interpreterIdentifier(code[i]) || code[i] == '\\' {
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
	return []interpreterToken{{text: value.String()}}, i, true
}
