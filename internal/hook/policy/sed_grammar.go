package policy

import (
	"github.com/avhn/secret/internal/hook/roles"
	"strings"
)

// sedParser consumes complete sed commands rather than searching for dangerous letters.
type sedParser struct {
	code        string
	pos, blocks int
	a           *analyzer
	depth       int
	cwd         string
}

// sedDelimited consumes an escaped-delimiter expression, including bracket classes.
func (p *sedParser) sedDelimited(delim byte, regex bool) bool {
	inClass := false
	for p.pos < len(p.code) {
		c := p.code[p.pos]
		p.pos++
		if c == '\\' {
			if p.pos >= len(p.code) {
				return false
			}
			p.pos++
			continue
		}
		if regex && c == '[' {
			inClass = true
		} else if regex && c == ']' {
			inClass = false
		}
		if c == delim {
			// GNU sed does not let a bracket class hide the delimiter; treating it
			// as hidden would misparse what follows, so the form is ambiguous.
			return !inClass
		}
	}
	return false
}

// sedAddress consumes one numeric, dollar, slash or custom-delimiter address.
func (p *sedParser) sedAddress() bool {
	if p.pos >= len(p.code) {
		return false
	}
	start := p.pos
	switch c := p.code[p.pos]; {
	case c >= '0' && c <= '9':
		for p.pos < len(p.code) && p.code[p.pos] >= '0' && p.code[p.pos] <= '9' {
			p.pos++
		}
		if p.pos < len(p.code) && p.code[p.pos] == '~' {
			p.pos++
			if !p.sedDigits() {
				return false
			}
		}
	case c == '$':
		p.pos++
	case c == '/':
		p.pos++
		if !p.sedDelimited('/', true) {
			return false
		}
		p.sedRegexFlags()
	case c == '\\':
		p.pos++
		if p.pos >= len(p.code) || p.code[p.pos] == '\n' {
			return false
		}
		delim := p.code[p.pos]
		p.pos++
		if !p.sedDelimited(delim, true) {
			return false
		}
		p.sedRegexFlags()
	default:
		return false
	}
	return p.pos > start
}

// sedDigits consumes an unsigned decimal operand.
func (p *sedParser) sedDigits() bool {
	start := p.pos
	for p.pos < len(p.code) && p.code[p.pos] >= '0' && p.code[p.pos] <= '9' {
		p.pos++
	}
	return p.pos > start
}

// sedRegexFlags accepts the address modifiers supported by GNU and BSD sed.
func (p *sedParser) sedRegexFlags() {
	for p.pos < len(p.code) && (p.code[p.pos] == 'I' || p.code[p.pos] == 'M') {
		p.pos++
	}
}

// sedSpaces consumes horizontal whitespace, preserving command-separating newlines.
func (p *sedParser) sedSpaces() {
	for p.pos < len(p.code) && (p.code[p.pos] == ' ' || p.code[p.pos] == '\t' || p.code[p.pos] == '\r') {
		p.pos++
	}
}

// sedArgument consumes a command argument until a separator or closing block.
func (p *sedParser) sedArgument() string {
	start := p.pos
	for p.pos < len(p.code) && !strings.ContainsRune(";\n}", rune(p.code[p.pos])) {
		p.pos++
	}
	return strings.TrimSpace(p.code[start:p.pos])
}

// sedLineArgument consumes a filename or shell fragment through the line end.
// Semicolons and braces inside these operands are not sed command separators.
func (p *sedParser) sedLineArgument() string {
	start := p.pos
	for p.pos < len(p.code) && p.code[p.pos] != '\n' {
		p.pos++
	}
	return strings.TrimSpace(p.code[start:p.pos])
}

// parseSedScript validates all source and checks every file or execution surface.
func (a *analyzer) parseSedScript(code string, depth int, cwd string) {
	p := sedParser{code: code, a: a, depth: depth, cwd: cwd}
	invalid := func() { a.reason = roles.Indeterminate }
	for p.pos < len(code) && a.reason == "" {
		p.sedSpaces()
		if p.pos == len(code) {
			break
		}
		if code[p.pos] == ';' || code[p.pos] == '\n' {
			p.pos++
			continue
		}
		if code[p.pos] == '#' {
			// GNU sed comments consume semicolons and braces through the newline.
			p.sedLineArgument()
			continue
		}
		if code[p.pos] == '}' {
			if p.blocks == 0 {
				invalid()
				break
			}
			p.blocks--
			p.pos++
			continue
		}
		if p.sedAddress() {
			p.sedSpaces()
			if p.pos < len(code) && code[p.pos] == ',' {
				p.pos++
				p.sedSpaces()
				if p.pos < len(code) && (code[p.pos] == '+' || code[p.pos] == '~') {
					p.pos++
					if !p.sedDigits() {
						invalid()
						break
					}
				} else if !p.sedAddress() {
					invalid()
					break
				}
			}
			p.sedSpaces()
		}
		if p.pos < len(code) && code[p.pos] == '!' {
			p.pos++
			p.sedSpaces()
		}
		if p.pos == len(code) {
			invalid()
			break
		}
		cmd := code[p.pos]
		p.pos++
		switch cmd {
		case '{':
			p.blocks++
			continue
		case 's', 'y':
			if p.pos >= len(code) || strings.ContainsRune(" \t\n;\\", rune(code[p.pos])) {
				invalid()
				break
			}
			delim := code[p.pos]
			p.pos++
			if !p.sedDelimited(delim, cmd == 's') || !p.sedDelimited(delim, false) {
				invalid()
				break
			}
			if cmd == 's' {
				for p.pos < len(code) && !strings.ContainsRune(";\n}", rune(code[p.pos])) {
					switch code[p.pos] {
					case ' ', '\t', '\r':
						p.pos++
					case 'g', 'p', 'P', 'I', 'M', 'e':
						if code[p.pos] == 'e' {
							a.reason = roles.Indeterminate
						}
						p.pos++
					case 'w':
						p.pos++
						file := p.sedLineArgument()
						if file == "" {
							invalid()
						} else if a.inputProtected(file, cwd) {
							a.reason = roles.FileInput
						}
					default:
						if !p.sedDigits() {
							invalid()
						}
					}
					if a.reason != "" {
						break
					}
				}
			}
		case 'r', 'R', 'w', 'W':
			p.sedSpaces()
			file := p.sedLineArgument()
			if file == "" {
				invalid()
			} else if a.inputProtected(file, cwd) {
				a.reason = roles.FileInput
			}
		case 'e':
			p.sedSpaces()
			value := p.sedLineArgument()
			if value == "" {
				invalid()
			} else {
				a.shellValue(value, depth, cwd)
			}
		case 'a', 'i', 'c':
			// Text includes semicolons and braces; backslash continues the next line.
			for p.pos < len(code) {
				if code[p.pos] == '\n' {
					backslashes := 0
					for i := p.pos - 1; i >= 0 && code[i] == '\\'; i-- {
						backslashes++
					}
					if backslashes%2 == 1 {
						p.pos++
						continue
					}
					break
				}
				p.pos++
			}
			if strings.TrimSpace(code[p.pos:]) != "" {
				invalid() // Later commands after text cannot be certified.
			}
		case ':', 'b', 't', 'T', 'v':
			p.sedArgument()
		case 'q', 'Q', 'l', 'L':
			p.sedSpaces()
			p.sedDigits()
		case 'd', 'D', 'p', 'P', 'n', 'N', 'h', 'H', 'g', 'G', 'x', 'z', '=', 'F':
		default:
			invalid()
		}
		if a.reason != "" {
			break
		}
		p.sedSpaces()
		if p.pos < len(code) && !strings.ContainsRune(";\n}", rune(code[p.pos])) {
			invalid()
		}
	}
	if a.reason == "" && p.blocks != 0 {
		invalid()
	}
}
