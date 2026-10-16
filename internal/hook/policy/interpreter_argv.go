package policy

import (
	"strconv"
	"strings"
)

// These tokens identify literal launch signatures, not a language evaluator.
// Unknown expressions, interpolation and unsupported escapes never supply an
// argv witness. Existing file/environment/string witnesses still run separately.
type interpreterToken struct {
	text    string
	literal bool
	shell   bool
}

func interpreterTokens(code, name string) []interpreterToken {
	hashComments := pythonInterpreter(name) || optionIn("ruby perl php rscript", name)
	slashComments := optionIn("node nodejs php", name)
	statementLines := optionIn("ruby perl", name)
	var tokens []interpreterToken
	for i := 0; i < len(code); {
		ch := code[i]
		if strings.ContainsRune(" \t\r\n", rune(ch)) {
			if ch == '\n' && statementLines {
				tokens = append(tokens, interpreterToken{text: "\n"})
			}
			i++
			continue
		}
		// Python floor division and Perl's defined-or operator are not
		// comments. Node's # is data (except for an initial hashbang).
		if ch == '#' && (hashComments || i == 0 && strings.HasPrefix(code, "#!")) || slashComments && strings.HasPrefix(code[i:], "//") {
			if end := strings.IndexByte(code[i:], '\n'); end >= 0 {
				i += end
				continue
			}
			break
		}
		if slashComments && strings.HasPrefix(code[i:], "/*") {
			if end := strings.Index(code[i+2:], "*/"); end >= 0 {
				i += end + 4
				continue
			}
			break
		}
		if ch == '/' && optionIn("node nodejs ruby perl", name) && interpreterRegexStart(tokens) {
			if end := interpreterRegexEnd(code, i); end > i {
				tokens = append(tokens, interpreterToken{text: code[i:end]})
				i = end
				continue
			}
		}
		if pythonInterpreter(name) {
			if token, end, ok := pythonLiteralToken(code, i); ok {
				tokens = append(tokens, token)
				i = end
				continue
			}
		}
		if ch == '\'' || ch == '"' || ch == '`' {
			start := i
			delimiter := string(ch)
			i += len(delimiter)
			var value strings.Builder
			shell := ch == '`' && optionIn("ruby perl", name)
			known, closed := ch != '`' || shell, false
			for i < len(code) {
				if strings.HasPrefix(code[i:], delimiter) {
					i += len(delimiter)
					closed = true
					break
				}
				r, _, tail, err := strconv.UnquoteChar(code[i:], ch)
				if err != nil {
					known = false
					// Keep scanning to the closing delimiter without mistaking
					// escaped quotes for another language literal.
					if code[i] == '\\' && i+1 < len(code) {
						i++
					}
					i++
					continue
				}
				value.WriteRune(r)
				i = len(code) - len(tail)
			}
			// Identifier-adjacent literals and double-quoted interpolation do
			// not supply a fully literal argv element.
			if start > 0 && interpreterIdentifier(code[start-1]) || ch == '"' && (strings.Contains(value.String(), "$") || strings.Contains(value.String(), "#{")) {
				known = false
			}
			tokens = append(tokens, interpreterToken{text: value.String(), literal: known && closed, shell: shell})
			continue
		}
		start := i
		if interpreterIdentifier(ch) {
			for i < len(code) && (interpreterIdentifier(code[i]) || code[i] == '.' || code[i] == ':') {
				i++
			}
		} else {
			i++
		}
		tokens = append(tokens, interpreterToken{text: code[start:i]})
	}
	return tokens
}

// Slash-delimited regex literals are opaque data, including escaped slashes,
// quotes and # inside character classes. Only expression-start positions are
// recognized; division and defined-or operators remain ordinary source tokens.
func interpreterRegexStart(tokens []interpreterToken) bool {
	if len(tokens) == 0 {
		return true
	}
	prior := tokens[len(tokens)-1]
	return !prior.literal && (optionIn("= ( [ { , : ; ! ? & | ~ return throw case", prior.text) || prior.text == "\n")
}

func interpreterRegexEnd(code string, start int) int {
	class := false
	for i := start + 1; i < len(code) && code[i] != '\n'; i++ {
		switch code[i] {
		case '\\':
			i++
		case '[':
			class = true
		case ']':
			class = false
		case '/':
			if !class {
				i++
				for i < len(code) && interpreterIdentifier(code[i]) {
					i++
				}
				return i
			}
		}
	}
	return start
}

func interpreterIdentifier(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '$'
}

// literalArguments accepts only a complete comma-separated literal sequence.
// The returned index points after the closing delimiter. Empty and trailing-
// comma lists are valid, but concatenation and expressions are not argv.
func literalArguments(tokens []interpreterToken, start int, close string) ([]string, int, bool) {
	var words []string
	for start < len(tokens) {
		if tokens[start].text == "\n" && !tokens[start].literal {
			start++
			continue
		}
		if tokens[start].text == close && !tokens[start].literal {
			return words, start + 1, true
		}
		if !tokens[start].literal {
			return nil, start, false
		}
		words = append(words, tokens[start].text)
		start++
		for start < len(tokens) && tokens[start].text == "\n" && !tokens[start].literal {
			start++
		}
		if start >= len(tokens) {
			break
		}
		if tokens[start].text == close && !tokens[start].literal {
			return words, start + 1, true
		}
		if tokens[start].text != "," || tokens[start].literal {
			break
		}
		start++
	}
	return nil, start, false
}

// Ruby and Perl also accept system/exec LIST without parentheses. A complete
// literal list must end at a statement boundary, not an expression or modifier.
func literalStatementArguments(tokens []interpreterToken, start int) ([]string, bool) {
	var words []string
	for start < len(tokens) && tokens[start].literal {
		words = append(words, tokens[start].text)
		start++
		if start == len(tokens) {
			return words, true
		}
		next := tokens[start]
		if !next.literal && (next.text == ";" || next.text == "}" || next.text == "\n") {
			return words, true
		}
		if next.literal || next.text != "," {
			return nil, false
		}
		start++
	}
	return nil, false
}

func (a *analyzer) interpreterArgvProtected(code, cwd, language string) bool {
	tokens := interpreterTokens(code, language)
	for i := 0; i < len(tokens); i++ {
		if tokens[i].literal {
			if tokens[i].shell && a.literalShellProtected(tokens[i].text, cwd) {
				return true
			}
			continue
		}
		if i+1 >= len(tokens) {
			continue
		}
		name := tokens[i].text
		if dot := strings.LastIndexAny(name, ".:"); dot >= 0 {
			name = name[dot+1:]
		}
		start := i + 2
		var words []string
		var known bool
		if tokens[i+1].text != "(" || tokens[i+1].literal {
			if optionIn("ruby perl", language) && optionIn("system exec", name) {
				words, known = literalStatementArguments(tokens, i+1)
			}
			if known {
				if len(words) == 1 && a.literalShellProtected(words[0], cwd) || len(words) > 1 && a.literalCommandProtected(words, cwd, true) {
					return true
				}
			}
			continue
		}
		if start >= len(tokens) {
			continue
		}
		// These APIs accept a shell-command literal as their first argument.
		// Later options or callbacks do not change that literal witness.
		shellAPI := optionIn("run call check_call check_output Popen system exec execSync", name)
		if pythonInterpreter(language) {
			// Python exec evaluates Python source; os.popen launches a shell.
			shellAPI = name != "exec" && (shellAPI || name == "popen")
		}
		if shellAPI && tokens[start].literal && start+1 < len(tokens) && !tokens[start+1].literal && optionIn(", )", tokens[start+1].text) {
			shell := !optionIn("system exec", name) || optionIn("node nodejs", language) || tokens[start+1].text == ")"
			if shell && a.literalShellProtected(tokens[start].text, cwd) {
				return true
			}
		}
		switch name {
		case "run", "call", "check_call", "check_output", "Popen":
			if tokens[start].text == "[" && !tokens[start].literal {
				var end int
				words, end, known = literalArguments(tokens, start+1, "]")
				known = known && end < len(tokens) && !tokens[end].literal && (tokens[end].text == "," || tokens[end].text == ")")
			}
		case "execv", "execvp", "execve", "execvpe", "spawn", "spawnSync", "execFile", "execFileSync":
			if start+2 < len(tokens) && tokens[start].literal && tokens[start+1].text == "," && !tokens[start+1].literal && tokens[start+2].text == "[" && !tokens[start+2].literal {
				var end int
				words, end, known = literalArguments(tokens, start+3, "]")
				known = known && end < len(tokens) && !tokens[end].literal && (tokens[end].text == "," || tokens[end].text == ")")
				if strings.HasPrefix(name, "execv") && len(words) > 0 {
					// Python's argv[0] is a label, not the selected executable.
					words = words[1:]
				}
				words = append([]string{tokens[start].text}, words...)
			}
		case "system", "exec":
			if name != "exec" || !pythonInterpreter(language) {
				words, _, known = literalArguments(tokens, start, ")")
			}
		}
		if known && a.literalCommandProtected(words, cwd, true) {
			return true
		}
	}
	return false
}
