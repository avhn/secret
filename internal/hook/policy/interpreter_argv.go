package policy

import (
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// These tokens identify literal launch signatures, not a language evaluator.
// Unknown expressions, interpolation and unsupported escapes never supply an
// argv witness. Existing file/environment/string witnesses still run separately.
type interpreterToken struct {
	text          string
	literal       bool // Fully static argv element.
	witness       bool // Closed source literal, even when interpolation is unresolved.
	shell         bool
	indeterminate bool     // A recognized literal did not terminate.
	opaque        bool     // Inert regex syntax, not unextracted executable source.
	regexCode     bool     // Ruby/Perl regex interpolation needs a bounded code scan.
	expressions   []string // Executable JavaScript template interpolations.
}

func interpreterTokens(code, name string) []interpreterToken {
	return interpreterBodyTokens(code, name, false)
}

func interpreterBodyTokens(code, name string, regexBody bool) []interpreterToken {
	hashComments := !regexBody && (pythonInterpreter(name) || optionIn("ruby perl php rscript", name))
	slashComments := javascriptInterpreter(name) || name == "php"
	statementLines := optionIn("ruby perl", name)
	regexWork, templateWork := 0, 0
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
		if luaVersion.MatchString(name) && strings.HasPrefix(code[i:], "--") {
			// Long comments can close before executable code on this line.
			// Reuse the exact long-string delimiter and incomplete-input rules.
			if token, end, ok := luaLiteralToken(code, i+2); ok {
				if token.indeterminate {
					tokens = append(tokens, token)
				}
				i = end
				continue
			}
			if end := strings.IndexByte(code[i:], '\n'); end >= 0 {
				i += end
				continue
			}
			break
		}
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
		if ch == '/' && (javascriptInterpreter(name) || optionIn("ruby perl", name)) {
			end, known := interpreterRegexEnd(code, i, &regexWork)
			if !known {
				return append(tokens, interpreterToken{indeterminate: true})
			}
			if end > i {
				text := code[i:end]
				interpolated := optionIn("ruby perl", name) && (strings.Contains(text, "#{") || strings.ContainsAny(text, "$@`"))
				// Bare Ruby/Perl calls can take an interpolating regex without
				// parentheses. Never let its # become a source line comment.
				if interpreterRegexStart(tokens) || interpolated {
					tokens = append(tokens, interpreterToken{text: text, opaque: !interpolated, regexCode: interpolated})
					i = end
					continue
				}
			}
		}
		if luaVersion.MatchString(name) {
			if token, end, ok := luaLiteralToken(code, i); ok {
				tokens = append(tokens, token)
				i = end
				continue
			}
		}
		if name == "perl" {
			if quoted, end, ok := perlLiteralTokens(code, i); ok {
				tokens = append(tokens, quoted...)
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
			var expressions []string
			shell := ch == '`' && optionIn("ruby perl php", name)
			known, closed := ch != '`' || shell || javascriptInterpreter(name), false
			for i < len(code) {
				if strings.HasPrefix(code[i:], delimiter) {
					i += len(delimiter)
					closed = true
					break
				}
				if ch == '`' && javascriptInterpreter(name) && strings.HasPrefix(code[i:], "${") {
					end, complete := javascriptInterpolationEnd(code, i+2, 0, &templateWork)
					if !complete {
						return append(tokens, interpreterToken{indeterminate: true})
					}
					expressions = append(expressions, code[i+2:end])
					value.WriteString(code[i : end+1])
					i = end + 1
					known = false
					continue
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
			// Interpolation syntax belongs to the source language, not every
			// double-quoted string. Lua/JavaScript/R strings do not expand $ or #{}.
			interpolated := ch == '"' && (name == "ruby" && (strings.Contains(value.String(), "#{") || strings.Contains(value.String(), "#$") || strings.Contains(value.String(), "#@")) || optionIn("perl php", name) && strings.ContainsAny(value.String(), "$@"))
			if start > 0 && interpreterIdentifier(code[start-1]) || interpolated {
				known = false
			}
			if ch == '`' && javascriptInterpreter(name) && strings.Contains(value.String(), "${") {
				known = false
			}
			tokens = append(tokens, interpreterToken{text: value.String(), literal: known && closed, witness: closed, shell: shell, indeterminate: !closed, expressions: expressions})
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
	return normalizeInterpreterMembers(tokens)
}

// Member-access whitespace is syntax, not part of an API name. Normalize only
// unquoted identifier chains so strings, regexes and statement boundaries remain
// data. All interpreter entry points use these same tokens before launch checks.
func normalizeInterpreterMembers(tokens []interpreterToken) []interpreterToken {
	identifier := func(token interpreterToken) bool {
		if token.literal || token.witness || token.opaque || token.regexCode || token.indeterminate || token.text == "" || !interpreterIdentifier(token.text[0]) {
			return false
		}
		// Numeric words have their own work-budget role. Do not merge them
		// into a member name and accidentally reduce the literal count.
		if token.text[0] >= '0' && token.text[0] <= '9' {
			return false
		}
		for i := range token.text {
			if !interpreterIdentifier(token.text[i]) && token.text[i] != '.' && token.text[i] != ':' {
				return false
			}
		}
		return true
	}
	next := func(i int) int {
		for i < len(tokens) && tokens[i].text == "\n" && !tokens[i].literal {
			i++
		}
		return i
	}
	out := tokens[:0]
	for i := 0; i < len(tokens); i++ {
		token := tokens[i]
		if identifier(token) {
			var member strings.Builder
			member.WriteString(token.text)
			for {
				j := next(i + 1)
				dot := !strings.HasSuffix(tokens[i].text, ".")
				if dot {
					if j >= len(tokens) || tokens[j].literal || tokens[j].text != "." {
						break
					}
					j = next(j + 1)
				}
				if j >= len(tokens) || !identifier(tokens[j]) {
					break
				}
				if dot {
					member.WriteByte('.')
				}
				member.WriteString(tokens[j].text)
				i = j
			}
			token.text = member.String()
		}
		out = append(out, token)
	}
	return out
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

func interpreterRegexEnd(code string, start int, work *int) (int, bool) {
	class := false
	for i := start + 1; i < len(code) && code[i] != '\n'; i++ {
		// Failed slash candidates can overlap. Bound total scanning across
		// the source, rather than allowing quadratic malformed-regex work.
		*work += 1
		if *work > 1<<20 {
			return start, false
		}
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
				return i, true
			}
		}
	}
	return start, true
}

func interpreterIdentifier(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '$'
}

// literalArguments accepts only a complete comma-separated literal sequence.
// The returned index points after the closing delimiter. Empty and trailing-
// comma lists are valid, but concatenation and expressions are not argv.
func literalArguments(tokens []interpreterToken, start int, close string) ([]string, int, bool) {
	return literalArrayArguments(tokens, start, close, false)
}

// PHP argv arrays may spell out consecutive decimal integer keys, including
// mixed explicit and implicit entries. Only the next positional key is accepted;
// reordered, duplicate or computed keys are not certified as literal argv.
func literalArrayArguments(tokens []interpreterToken, start int, close string, phpKeys bool) ([]string, int, bool) {
	var words []string
	for start < len(tokens) {
		if tokens[start].text == "\n" && !tokens[start].literal {
			start++
			continue
		}
		if tokens[start].text == close && !tokens[start].literal {
			return words, start + 1, true
		}
		if phpKeys && start+3 < len(tokens) && !tokens[start].literal && tokens[start].text == strconv.Itoa(len(words)) &&
			!tokens[start+1].literal && tokens[start+1].text == "=" && !tokens[start+2].literal && tokens[start+2].text == ">" {
			start += 3
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
	tokens := interpreterBodyTokens(code, language, a.regexBody)
	for i := 0; i < len(tokens); i++ {
		if a.expired() {
			a.reason = roles.Indeterminate
			return true
		}
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
		if language == "php" {
			// PHP function names are case-insensitive, unlike JavaScript members.
			name = strings.ToLower(name)
		}
		start := i + 2
		if language == "ruby" && optionIn("system exec spawn", name) {
			statement := tokens[i+1].literal || tokens[i+1].text != "("
			if statement {
				start = i + 1
			}
			if words, known := rubyExecutableArguments(tokens, start, statement); known {
				if a.literalCommandProtected(words, cwd, true) {
					return true
				}
				continue
			}
			start = i + 2
		}
		if javascriptInterpreter(language) && (tokens[i].text == "Deno.Command" || strings.HasSuffix(tokens[i].text, ".Deno.Command")) && !tokens[i+1].literal && tokens[i+1].text == "(" {
			dirs := a.interpreterLaunchCwds(tokens, start, "Deno.Command", language, cwd)
			for _, words := range constructorArguments(tokens, start) {
				if a.literalCommandProtected(words, cwd, true) {
					return true
				}
				for _, dir := range dirs {
					if a.literalCommandProtected(words, dir, true) {
						return true
					}
				}
			}
		}
		var words []string
		var known bool
		if tokens[i+1].text != "(" || tokens[i+1].literal {
			if optionIn("ruby perl", language) && (optionIn("system exec", name) || language == "ruby" && name == "spawn") {
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
		shellAPI := optionIn("run call check_call check_output Popen system exec execSync", name) || language == "php" && name == "proc_open"
		if pythonInterpreter(language) {
			// Python exec evaluates Python source; os.popen launches a shell.
			shellAPI = name != "exec" && (shellAPI || name == "popen")
		}
		if shellAPI && tokens[start].literal && start+1 < len(tokens) && !tokens[start+1].literal && optionIn(", )", tokens[start+1].text) {
			shell := !optionIn("system exec", name) || optionIn("node nodejs", language) || tokens[start+1].text == ")"
			if shell {
				if a.literalShellProtected(tokens[start].text, cwd) {
					return true
				}
				for _, dir := range a.interpreterLaunchCwds(tokens, start, name, language, cwd) {
					if a.literalShellProtected(tokens[start].text, dir) {
						return true
					}
				}
			}
		}
		switch name {
		case "run", "call", "check_call", "check_output", "Popen", "popen", "proc_open":
			if name == "proc_open" && language != "php" {
				break
			}
			if tokens[start].text == "[" && !tokens[start].literal {
				var end int
				words, end, known = literalArrayArguments(tokens, start+1, "]", language == "php" && name == "proc_open")
				known = known && end < len(tokens) && !tokens[end].literal && (tokens[end].text == "," || tokens[end].text == ")")
			} else if name == "proc_open" && !tokens[start].literal && strings.EqualFold(tokens[start].text, "array") && start+1 < len(tokens) && !tokens[start+1].literal && tokens[start+1].text == "(" {
				// PHP's array(...) constructor is the same literal argv container
				// as [...]. Keep its closing delimiter separate from proc_open's.
				var end int
				words, end, known = literalArrayArguments(tokens, start+2, ")", true)
				known = known && end < len(tokens) && !tokens[end].literal && optionIn(", )", tokens[end].text)
			}
		case "execv", "execvp", "execve", "execvpe", "spawn", "spawnSync", "execFile", "execFileSync":
			if tokens[start].text == "[" && !tokens[start].literal {
				var end int
				words, end, known = literalArguments(tokens, start+1, "]")
				known = known && end < len(tokens) && !tokens[end].literal && optionIn(", )", tokens[end].text)
			} else if language == "ruby" && name == "spawn" {
				words, _, known = literalArguments(tokens, start, ")")
			} else if start+2 < len(tokens) && tokens[start].literal && tokens[start+1].text == "," && !tokens[start+1].literal && tokens[start+2].text == "[" && !tokens[start+2].literal {
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
		if known {
			if a.literalCommandProtected(words, cwd, true) {
				return true
			}
			for _, dir := range a.interpreterLaunchCwds(tokens, start, name, language, cwd) {
				if a.literalCommandProtected(words, dir, true) {
					return true
				}
			}
		}
	}
	return false
}
