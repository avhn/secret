package search

import "strings"

// Grep's host builder splits whitespace first, then comma lists unless the
// token contains both braces. Preserve those host selectors and also check
// top-level comma alternatives to retain Bash's protected-name denials.
func grepGlobs(glob string) ([]string, bool) {
	if len(glob) > 4096 {
		return nil, false
	}
	var selectors []string
	for _, token := range strings.Fields(glob) {
		// Failed brace enumeration cannot fall through to a names-only allow.
		if _, ok := selectorBraces(token, 64); !ok {
			return nil, false
		}
		if strings.Contains(token, "{") && strings.Contains(token, "}") {
			selectors = append(selectors, token)
			depth, last := 0, 0
			for i, c := range token {
				switch c {
				case '{':
					depth++
				case '}':
					depth--
				case ',':
					if depth == 0 {
						selectors = append(selectors, token[last:i])
						last = i + 1
					}
				}
			}
			if last > 0 {
				selectors = append(selectors, token[last:])
			}
		} else {
			selectors = append(selectors, strings.Split(token, ",")...)
		}
		if len(selectors) > 64 {
			return nil, false
		}
	}
	return selectors, true
}
