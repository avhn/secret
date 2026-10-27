// Package ps recognizes a bounded, non-executing PowerShell subset. It is not a
// general PowerShell parser, and is not enabled by the production hook.
package ps

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	MaxSource = 40 * 1024
	MaxTokens = 4096
	MaxNodes  = 2048
	MaxWords  = 256
	MaxDepth  = 4
)

// Denial contains only a fixed category, never input, a path or a native error.
type Denial struct{ Reason string }

func (d *Denial) Error() string { return d.Reason }

const (
	ReasonSyntax      = "powershell malformed syntax"
	ReasonUnsupported = "powershell unsupported syntax"
	ReasonDirective   = "powershell directives are unsupported"
	ReasonLimit       = "powershell analysis limit exceeded"
	ReasonDeadline    = "powershell analysis deadline exceeded"
	ReasonPanic       = "powershell analysis failed"
	ReasonBinding     = "powershell parameter binding is unsupported"
	ReasonCommand     = "powershell command is unsupported"
	ReasonPipeline    = "powershell pipeline is not certified"
	ReasonPath        = "powershell file operand is unsupported"
	ReasonContext     = "powershell native context is invalid"
	ReasonRead        = "reader targets a protected store"
	ReasonWrite       = "powershell write targets a protected file or configuration"
	ReasonMetadata    = "powershell file kind is not certified"
)

// Only the analyzer creates this private unwind signal. A callback that panics
// with an exported Denial must not smuggle arbitrary text into a decision.
type rejection string

func deny(reason string) { panic(rejection(reason)) }

// Span is a half-open byte interval in the original UTF-8 source. Projection
// converts it to PowerShell's UTF-16 offset convention.
type Span struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type Token struct {
	Kind  string `json:"kind"`
	Text  string `json:"text"`
	Span  Span   `json:"span"`
	Value string `json:"-"`
	Quote string `json:"-"`
}

type Word struct {
	Value string
	Quote string
	Span  Span
	Colon bool
}
type Argument struct {
	Word  *Word
	Block *Script
	Span  Span
}
type Redirect struct {
	Stream int
	Append bool
	Merge  int
	Target *Word
	Span   Span
}
type Command struct {
	Name      Word
	Arguments []Argument
	Redirects []Redirect
	Span      Span
}
type Pipeline struct {
	Commands []Command
	Span     Span
}
type Script struct {
	Pipelines []Pipeline
	Span      Span
}
type Tree struct {
	Tokens []Token
	Script Script
}

type budget struct {
	ctx      context.Context
	deadline time.Time
	now      func() time.Time
	nodes    int
}

func (b *budget) check() {
	if b.ctx != nil && b.ctx.Err() != nil {
		deny(ReasonDeadline)
	}
	if !b.deadline.IsZero() && !b.now().Before(b.deadline) {
		deny(ReasonDeadline)
	}
}
func (b *budget) node() {
	b.check()
	b.nodes++
	if b.nodes > MaxNodes {
		deny(ReasonLimit)
	}
}
func recoverDenial(err *error) {
	if v := recover(); v != nil {
		if reason, ok := v.(rejection); ok {
			*err = &Denial{string(reason)}
		} else {
			*err = &Denial{ReasonPanic}
		}
	}
}

// Parse consumes the complete request. Every returned error is a *Denial.
// The same budget is used for scanning, construction, and policy traversal.
func Parse(src []byte, ctx context.Context) (tree *Tree, err error) {
	defer func() {
		if err != nil {
			tree = nil
		}
	}()
	defer recoverDenial(&err)
	b := &budget{ctx: ctx, now: time.Now}
	return parse(src, b), nil
}

func parse(src []byte, b *budget) *Tree {
	b.check()
	if len(src) > MaxSource {
		deny(ReasonLimit)
	}
	if !utf8.Valid(src) {
		deny(ReasonSyntax)
	}
	// These checks also cover comments and otherwise inactive nested text. Do not
	// normalize Unicode lookalikes into executable syntax.
	for i := 0; i < len(src); {
		b.check()
		r, n := utf8.DecodeRune(src[i:])
		i += n
		if (unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t') || unicode.Is(unicode.Cf, r) {
			deny(ReasonUnsupported)
		}
		if r == '\r' && (i == len(src) || src[i] != '\n') {
			deny(ReasonSyntax)
		}
		if strings.ContainsRune("‘’‚‛“”„‟«»‐‑‒–—―−﹣－", r) {
			deny(ReasonUnsupported)
		}
	}
	tokens := scan(src, b)
	p := parser{tokens: tokens, b: b}
	root := p.script(0, false)
	root.Span = Span{0, len(src)}
	return &Tree{Tokens: tokens, Script: root}
}

func scan(src []byte, b *budget) []Token {
	out := make([]Token, 0)
	add := func(kind string, start, end int, value, quote string) {
		b.check()
		// Native argument parsing recognizes the decoded value even when quoted.
		// Keep this at the shared token boundary for every literal-word path.
		if kind == "word" && value == "--%" {
			deny(ReasonUnsupported)
		}
		if len(out) == MaxTokens {
			deny(ReasonLimit)
		}
		out = append(out, Token{kind, string(src[start:end]), Span{start, end}, value, quote})
	}
	for i := 0; i < len(src); {
		b.check()
		start := i
		c := src[i]
		if c == ' ' || c == '\t' {
			i++
			continue
		}
		if c == '\r' {
			i += 2
			add("separator", start, i, "", "")
			continue
		}
		if c == '#' {
			for i < len(src) && src[i] != '\n' && src[i] != '\r' {
				b.check()
				i++
			}
			text := strings.ToLower(string(src[start:i]))
			if strings.HasPrefix(text, "#requires") || strings.Contains(text, "sig # begin signature block") || strings.Contains(text, "sig # end signature block") || signatureComment(text[1:], b) {
				deny(ReasonDirective)
			}
			add("comment", start, i, "", "")
			continue
		}
		if c == '<' && i+1 < len(src) && src[i+1] == '#' {
			// PowerShell block comments do not nest: the first #> ends the
			// comment. A nested-looking opener is ambiguous to readers, so deny it.
			i += 2
			closed := false
			for i < len(src) && !closed {
				b.check()
				if i+1 < len(src) && src[i] == '<' && src[i+1] == '#' {
					deny(ReasonUnsupported)
				} else if i+1 < len(src) && src[i] == '#' && src[i+1] == '>' {
					closed = true
					i += 2
				} else {
					i++
				}
			}
			if !closed {
				deny(ReasonSyntax)
			}
			text := strings.ToLower(string(src[start:i]))
			if strings.Contains(text, "#requires") || strings.Contains(text, "sig # begin signature block") || strings.Contains(text, "sig # end signature block") || signatureComment(text[2:len(text)-2], b) {
				deny(ReasonDirective)
			}
			add("comment", start, i, "", "")
			continue
		}
		if c == '<' || c == '`' || c == '&' || c == '$' || c == '@' || c == '(' || c == ')' || c == '[' || c == ']' || c == ',' || c == '=' {
			deny(ReasonUnsupported)
		}
		kinds := map[byte]string{'\n': "separator", ';': "separator", '|': "pipe", '{': "block_start", '}': "block_end"}
		if kind, ok := kinds[c]; ok {
			i++
			add(kind, start, i, "", "")
			continue
		}
		// Redirection must start at a token boundary. Adjacent word/operator forms
		// are rejected below rather than guessing PowerShell argument mode.
		if c == '>' || (c >= '1' && c <= '6' || c == '*') && i+1 < len(src) && src[i+1] == '>' {
			if c != '>' {
				i++
			}
			i++
			if i < len(src) && src[i] == '>' {
				i++
			}
			if i < len(src) && src[i] == '&' {
				i++
				if i == len(src) || src[i] != '1' {
					deny(ReasonUnsupported)
				}
				i++
			}
			if i < len(src) && src[i] != ' ' && src[i] != '\t' && src[i] != '\r' && src[i] != '\n' && src[i] != ';' && src[i] != '}' {
				deny(ReasonUnsupported)
			}
			add("redirect", start, i, "", "")
			continue
		}
		if c == '\'' || c == '"' {
			quote := c
			i++
			var value strings.Builder
			closed := false
			for i < len(src) {
				b.check()
				c = src[i]
				if c == '`' {
					deny(ReasonUnsupported)
				}
				if c == quote {
					i++
					if quote == '\'' && i < len(src) && src[i] == '\'' {
						value.WriteByte('\'')
						i++
						continue
					}
					closed = true
					break
				}
				if quote == '"' && c == '$' {
					deny(ReasonUnsupported)
				}
				value.WriteByte(c)
				i++
			}
			if !closed {
				deny(ReasonSyntax)
			}
			if !wordBoundary(src, i) {
				deny(ReasonUnsupported)
			}
			add("word", start, i, value.String(), string(quote))
			continue
		}
		// A parameter's colon argument is a separate literal token, even without
		// whitespace. This preserves the parameter extent from the native AST.
		if c == '-' {
			i++
			for i < len(src) && asciiLetter(src[i]) {
				b.check()
				i++
			}
			if i > start+1 && i < len(src) && src[i] == ':' {
				i++
				add("parameter", start, i, string(src[start+1:i-1]), "")
				continue
			}
			i = start
		}
		for i < len(src) && !wordBoundary(src, i) {
			b.check()
			c = src[i]
			if c >= 128 || strings.ContainsRune("'\"`$@()[]{},=&<>*?", rune(c)) {
				deny(ReasonUnsupported)
			}
			i++
		}
		if i == start {
			deny(ReasonSyntax)
		}
		text := string(src[start:i])
		// PowerShell parses numeric-looking command arguments as expressions,
		// potentially changing their spelling before path binding (01, 0x10,
		// 1e2). Require quotes instead of certifying the wrong native path.
		if text[0] >= '0' && text[0] <= '9' || text[0] == '+' || text[0] == '!' || len(text) > 1 && text[0] == '.' && text[1] >= '0' && text[1] <= '9' {
			deny(ReasonUnsupported)
		}
		if text == "--" || text == "--%" {
			deny(ReasonUnsupported)
		}
		kind := "word"
		value := text
		if strings.HasPrefix(text, "-") && len(text) > 1 {
			for j := 1; j < len(text); j++ {
				if !asciiLetter(text[j]) {
					deny(ReasonUnsupported)
				}
			}
			kind = "parameter"
			value = text[1:]
		}
		add(kind, start, i, value, "")
	}
	return out
}

// signatureComment deliberately over-denies native signature-like comments.
// PowerShell ignores whitespace and case and tolerates near-miss markers. Scan
// the whole bounded comment for markers, but cap edit-distance work to prefixes
// that could be within ten edits of a begin/end marker, even with trailing text.
func signatureComment(text string, b *budget) bool {
	var normalized strings.Builder
	for _, r := range text {
		b.check()
		if !unicode.IsSpace(r) {
			normalized.WriteRune(unicode.ToLower(r))
		}
	}
	value := normalized.String()
	if strings.Contains(value, "sig#") || strings.Contains(value, "signatureblock") {
		return true
	}
	const distance = 10
	for _, marker := range []string{"sig#beginsignatureblock", "sig#endsignatureblock"} {
		b.check()
		// Both dimensions are fixed by the marker length and distance, never
		// the source length. Each row is the distance for one bounded prefix.
		previous := make([]int, len(marker)+1)
		current := make([]int, len(marker)+1)
		for j := range previous {
			previous[j] = j
		}
		i := 0
		for _, r := range value {
			b.check()
			i++
			if i > len(marker)+distance {
				break
			}
			current[0] = i
			for j := 1; j <= len(marker); j++ {
				cost := 1
				if r == rune(marker[j-1]) {
					cost = 0
				}
				current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
			}
			if current[len(marker)] <= distance {
				return true
			}
			previous, current = current, previous
		}
	}
	b.check()
	return false
}

func asciiLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
func wordBoundary(src []byte, i int) bool {
	return i == len(src) || strings.ContainsRune(" \t\r\n;|{}", rune(src[i]))
}

type parser struct {
	tokens []Token
	pos    int
	b      *budget
}

func (p *parser) skipComments() {
	for p.pos < len(p.tokens) && p.tokens[p.pos].Kind == "comment" {
		p.b.check()
		p.pos++
	}
}
func (p *parser) peek() string {
	p.b.check()
	p.skipComments()
	if p.pos == len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos].Kind
}
func (p *parser) take() Token { p.b.check(); t := p.tokens[p.pos]; p.pos++; return t }
func (p *parser) word() Word {
	if p.peek() != "word" && p.peek() != "parameter" {
		deny(ReasonSyntax)
	}
	t := p.take()
	p.b.node()
	return Word{Value: t.Value, Quote: t.Quote, Span: t.Span, Colon: t.Kind == "parameter" && strings.HasSuffix(t.Text, ":")}
}
func (p *parser) script(depth int, nested bool) Script {
	p.b.node()
	root := Script{}
	for {
		for p.peek() == "separator" {
			p.take()
		}
		kind := p.peek()
		if kind == "" {
			if nested {
				deny(ReasonSyntax)
			}
			break
		}
		if kind == "block_end" {
			if !nested {
				deny(ReasonSyntax)
			}
			break
		}
		pipe := p.pipeline(depth)
		root.Pipelines = append(root.Pipelines, pipe)
		kind = p.peek()
		if kind != "" && kind != "separator" && kind != "block_end" {
			deny(ReasonSyntax)
		}
	}
	return root
}
func (p *parser) pipeline(depth int) Pipeline {
	p.b.node()
	pipe := Pipeline{}
	for {
		c := p.command(depth)
		pipe.Commands = append(pipe.Commands, c)
		if p.peek() != "pipe" {
			break
		}
		p.take()
		// PowerShell permits a newline after a pipe, not an empty pipeline stage.
		for p.peek() == "separator" && (p.tokens[p.pos].Text == "\n" || p.tokens[p.pos].Text == "\r\n") {
			p.take()
		}
	}
	pipe.Span = Span{pipe.Commands[0].Span.Start, pipe.Commands[len(pipe.Commands)-1].Span.End}
	return pipe
}
func (p *parser) command(depth int) Command {
	p.b.node()
	if p.peek() != "word" {
		deny(ReasonSyntax)
	}
	c := Command{Name: p.word()}
	c.Span = c.Name.Span
	words := 1
	for {
		kind := p.peek()
		if kind == "" || kind == "separator" || kind == "pipe" || kind == "block_end" {
			break
		}
		p.b.node()
		if kind == "redirect" {
			t := p.take()
			r := Redirect{Stream: 1, Span: t.Span}
			text := t.Text
			if text[0] != '>' {
				if text[0] == '*' {
					r.Stream = -1
				} else {
					r.Stream = int(text[0] - '0')
				}
				text = text[1:]
			}
			r.Append = strings.HasPrefix(text, ">>")
			if strings.Contains(text, "&") {
				if r.Append || r.Stream == 1 {
					deny(ReasonUnsupported)
				}
				r.Merge = 1
			} else {
				if p.peek() != "word" {
					deny(ReasonSyntax)
				}
				words++
				if words > MaxWords {
					deny(ReasonLimit)
				}
				w := p.word()
				r.Target = &w
				r.Span.End = w.Span.End
			}
			c.Redirects = append(c.Redirects, r)
			c.Span.End = r.Span.End
			continue
		}
		words++
		if words > MaxWords {
			deny(ReasonLimit)
		}
		if kind == "block_start" {
			if depth == MaxDepth {
				deny(ReasonLimit)
			}
			open := p.take()
			block := p.script(depth+1, true)
			if p.peek() != "block_end" {
				deny(ReasonSyntax)
			}
			close := p.take()
			block.Span = Span{open.Span.Start, close.Span.End}
			c.Arguments = append(c.Arguments, Argument{Block: &block, Span: block.Span})
			c.Span.End = close.Span.End
			continue
		}
		if kind != "word" && kind != "parameter" {
			deny(ReasonSyntax)
		}
		t := p.tokens[p.pos]
		w := p.word()
		// Keep parameter spelling distinct from quoted dash-prefixed data.
		if t.Kind == "parameter" {
			w.Quote = "parameter"
		}
		c.Arguments = append(c.Arguments, Argument{Word: &w, Span: w.Span})
		c.Span.End = w.Span.End
	}
	return c
}
