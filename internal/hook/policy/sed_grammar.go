package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// sedParser certifies only the safe subset shared with the shell guard.
type sedParser struct {
	code        string
	pos, blocks int
	a           *analyzer
	cwd         string
}

func (p *sedParser) digits() bool {
	start := p.pos
	for p.pos < len(p.code) && p.code[p.pos] >= '0' && p.code[p.pos] <= '9' {
		p.pos++
	}
	return p.pos > start
}

func (p *sedParser) delimited(delim byte) bool {
	if delim == '\\' || delim == '\n' {
		return false
	}
	for p.pos < len(p.code) {
		c := p.code[p.pos]
		p.pos++
		if c == '\n' {
			return false
		}
		if c == '\\' {
			if p.pos >= len(p.code) || p.code[p.pos] == '\n' {
				return false
			}
			p.pos++
		} else if c == delim {
			return true
		}
	}
	return false
}

func (p *sedParser) address() bool {
	if p.pos >= len(p.code) {
		return false
	}
	switch c := p.code[p.pos]; {
	case c >= '0' && c <= '9':
		p.digits()
		if p.pos < len(p.code) && p.code[p.pos] == '~' {
			p.pos++
			return p.digits()
		}
	case c == '$':
		p.pos++
	case c == '/':
		p.pos++
		if !p.delimited('/') {
			return false
		}
		p.regexFlags()
	case c == '\\':
		p.pos++
		if p.pos >= len(p.code) {
			return false
		}
		d := p.code[p.pos]
		p.pos++
		if !p.delimited(d) {
			return false
		}
		p.regexFlags()
	default:
		return false
	}
	return true
}

func (p *sedParser) regexFlags() {
	for p.pos < len(p.code) && (p.code[p.pos] == 'I' || p.code[p.pos] == 'M') {
		p.pos++
	}
}
func (p *sedParser) spaces() {
	for p.pos < len(p.code) && (p.code[p.pos] == ' ' || p.code[p.pos] == '\t') {
		p.pos++
	}
}
func sedLabelChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.'
}
func sedFileChar(c byte) bool {
	return sedLabelChar(c) || strings.ContainsRune("/@+-", rune(c))
}
func sedSeparator(c byte) bool { return c == ';' || c == '\n' || c == '}' }

func (a *analyzer) parseSedScript(code string, _ int, cwd string) {
	p := sedParser{code: code, a: a, cwd: cwd}
	invalid := func() { a.reason = roles.Indeterminate }
	for p.pos < len(code) && a.reason == "" {
		p.spaces()
		if p.pos == len(code) {
			break
		}
		if code[p.pos] == ';' || code[p.pos] == '\n' {
			p.pos++
			continue
		}
		if code[p.pos] == '#' {
			// Comments must begin at the start of a line (apart from indentation).
			start := p.pos
			for start > 0 && (code[start-1] == ' ' || code[start-1] == '\t') {
				start--
			}
			if start > 0 && code[start-1] != '\n' {
				invalid()
				break
			}
			for p.pos < len(code) && code[p.pos] != '\n' {
				p.pos++
			}
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
		if p.address() {
			p.spaces()
			if p.pos < len(code) && code[p.pos] == ',' {
				p.pos++
				p.spaces()
				if p.pos < len(code) && (code[p.pos] == '+' || code[p.pos] == '~') {
					p.pos++
					if !p.digits() {
						invalid()
						break
					}
				} else if !p.address() {
					invalid()
					break
				}
			}
			p.spaces()
		}
		if p.pos < len(code) && code[p.pos] == '!' {
			p.pos++
			p.spaces()
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
			if p.pos >= len(code) {
				invalid()
				break
			}
			d := code[p.pos]
			p.pos++
			if !p.delimited(d) || !p.delimited(d) {
				invalid()
				break
			}
			if cmd == 's' {
				for p.pos < len(code) && !sedSeparator(code[p.pos]) {
					c := code[p.pos]
					if !(strings.ContainsRune("gp iImM", rune(c)) && c != ' ' || c >= '0' && c <= '9') {
						invalid()
						break
					}
					p.pos++
				}
			}
		case 'p', 'P', 'd', 'D', 'n', 'N', 'g', 'G', 'h', 'H', 'x', 'l', '=', 'q', 'Q', 'z':
		case ':', 'b', 't', 'T':
			p.spaces()
			start := p.pos
			for p.pos < len(code) && sedLabelChar(code[p.pos]) {
				p.pos++
			}
			if cmd == ':' && p.pos == start {
				invalid()
			}
			if p.pos < len(code) && code[p.pos] != ';' && code[p.pos] != '\n' {
				invalid()
			}
		case 'a', 'i', 'c':
			text := code[p.pos:]
			if strings.ContainsAny(text, "\\\n") {
				invalid()
				break
			}
			p.pos = len(code)
		case 'r', 'R', 'w', 'W':
			p.spaces()
			start := p.pos
			for p.pos < len(code) && code[p.pos] != '\n' {
				if !sedFileChar(code[p.pos]) {
					invalid()
					break
				}
				p.pos++
			}
			if a.reason != "" {
				break
			}
			if p.pos == start {
				invalid()
				break
			}
			file := code[start:p.pos]
			if cmd == 'r' || cmd == 'R' {
				if a.inputProtected(file, cwd) {
					a.reason = roles.FileInput
				}
			} else if a.inputProtected(file, cwd) || a.writeProtected(file, cwd) {
				a.reason = roles.FileInput
			}
		default:
			invalid()
		}
		if a.reason != "" {
			break
		}
		p.spaces()
		if p.pos < len(code) && !sedSeparator(code[p.pos]) {
			invalid()
		}
	}
	if a.reason == "" && p.blocks != 0 {
		invalid()
	}
}
