package policy

import "strings"

// Ruby's [executable, argv0] first operand selects an executable independently
// of its display name. Only complete literal pairs and argv tails are witnesses.
func rubyExecutableArguments(tokens []interpreterToken, start int, statement bool) ([]string, bool) {
	if start >= len(tokens) || tokens[start].literal || tokens[start].text != "[" {
		return nil, false
	}
	pair, end, known := literalArguments(tokens, start+1, "]")
	if !known || len(pair) != 2 {
		return nil, false
	}
	if statement && end == len(tokens) {
		return pair[:1], true
	}
	if end >= len(tokens) || tokens[end].literal {
		return nil, false
	}
	if tokens[end].text == ")" && !statement || statement && optionIn("; } \n", tokens[end].text) {
		return pair[:1], true
	}
	if tokens[end].text != "," {
		return nil, false
	}
	var tail []string
	if statement {
		tail, known = literalStatementArguments(tokens, end+1)
	} else {
		tail, _, known = literalArguments(tokens, end+1, ")")
	}
	return append(pair[:1], tail...), known
}

// Skip one object value without interpreting it. Balanced nested expressions
// cannot supply top-level option keys. Literal punctuation is always data.
func interpreterObjectValueEnd(tokens []interpreterToken, start int) (int, bool) {
	var closes []string
	for i := start; i < len(tokens); i++ {
		token := tokens[i]
		if token.literal || token.witness || token.opaque || token.regexCode {
			continue
		}
		if len(closes) == 0 && optionIn(", }", token.text) {
			return i, i > start
		}
		switch token.text {
		case "(", "[", "{":
			if len(closes) >= 64 {
				return i, false
			}
			closes = append(closes, map[string]string{"(": ")", "[": "]", "{": "}"}[token.text])
		case ")", "]", "}":
			if len(closes) == 0 || closes[len(closes)-1] != token.text {
				return i, false
			}
			closes = closes[:len(closes)-1]
		}
	}
	return len(tokens), false
}

func javascriptPropertyIdentifier(name string) bool {
	if name == "" || name[0] >= '0' && name[0] <= '9' {
		return false
	}
	for i := range name {
		if !interpreterIdentifier(name[i]) {
			return false
		}
	}
	return true
}

// Deno.Command takes its executable separately from options.args. Inspect every
// literal args occurrence rather than letting a later option erase a witness.
// Other option values are not argv, even when they contain an args-like key.
func constructorArguments(tokens []interpreterToken, start int) [][]string {
	if start+3 >= len(tokens) || !tokens[start].literal || tokens[start+1].literal || tokens[start+1].text != "," || tokens[start+2].literal || tokens[start+2].text != "{" {
		return nil
	}
	executable := tokens[start].text
	var launches [][]string
	for i := start + 3; i < len(tokens); {
		if !tokens[i].literal && tokens[i].text == "}" {
			if i+1 < len(tokens) && !tokens[i+1].literal && tokens[i+1].text == ")" {
				return launches
			}
			return nil
		}
		key := tokens[i]
		i++
		if !key.literal && strings.HasSuffix(key.text, ":") {
			key.text = strings.TrimSuffix(key.text, ":")
		} else {
			if i < len(tokens) && !key.literal && javascriptPropertyIdentifier(key.text) && !tokens[i].literal && optionIn(", }", tokens[i].text) {
				// Shorthand properties are unrelated option values, not a reason
				// to discard executable/args witnesses collected elsewhere.
				if tokens[i].text == "," {
					i++
				}
				continue
			}
			if i >= len(tokens) || tokens[i].literal || tokens[i].text != ":" {
				return nil
			}
			i++
		}
		end, known := interpreterObjectValueEnd(tokens, i)
		if !known {
			return nil
		}
		if key.text == "args" && i < len(tokens) && !tokens[i].literal && tokens[i].text == "[" {
			args, after, literal := literalArguments(tokens, i+1, "]")
			if literal && after == end {
				launches = append(launches, append([]string{executable}, args...))
			}
		}
		i = end
		if tokens[i].text == "," {
			i++
		}
	}
	return nil
}
