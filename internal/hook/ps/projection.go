package ps

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Projection is test-only structural evidence. Unlike Decision it contains
// synthetic source text and must never be used as hook diagnostics or audit.
// Spans use native PowerShell UTF-16 offsets. Native metadata is deliberately
// independent: the oracle reports all real sets, Go reports its modeled set.
// Step 4 must compare syntax and binding independently, and validate the modeled
// metadata against each native set, not equate the two metadata arrays.
type Projection struct {
	Tokens             []Token             `json:"tokens"`
	ParseErrors        []ProjectionError   `json:"parseErrors"`
	ScriptRequirements *Requirements       `json:"scriptRequirements"`
	Statements         []ProjectedPipeline `json:"statements"`
	Bindings           []ProjectedBinding  `json:"bindings"`
	Metadata           []CommandMetadata   `json:"metadata"`
	Unsupported        []string            `json:"unsupported"`
}
type Requirements struct {
	Present bool `json:"present"`
}
type ProjectionError struct {
	ID   string `json:"id"`
	Span Span   `json:"span"`
}
type ProjectedPipeline struct {
	Span     Span               `json:"span"`
	Commands []ProjectedCommand `json:"commands"`
	Edges    []Edge             `json:"edges"`
}
type Edge struct {
	From int `json:"from"`
	To   int `json:"to"`
}
type ProjectedCommand struct {
	Name               string              `json:"name"`
	InvocationOperator string              `json:"invocationOperator"`
	Span               Span                `json:"span"`
	Elements           []Element           `json:"elements"`
	Redirects          []ProjectedRedirect `json:"redirects"`
}
type Element struct {
	Kind       string              `json:"kind"`
	Value      string              `json:"value"`
	Quote      string              `json:"quote"`
	Colon      bool                `json:"colon"`
	Span       Span                `json:"span"`
	Statements []ProjectedPipeline `json:"statements"`
}
type ProjectedRedirect struct {
	Stream int      `json:"stream"`
	Append bool     `json:"append"`
	Merge  int      `json:"merge"`
	Target *Element `json:"target"`
	Span   Span     `json:"span"`
}
type ProjectedBinding struct {
	Span       Span             `json:"span"`
	Parameters []BoundParameter `json:"parameters"`
	Exceptions []string         `json:"exceptions"`
}
type BoundParameter struct {
	Name       string `json:"name"`
	Positional bool   `json:"positional"`
	Span       Span   `json:"span"`
}
type CommandMetadata struct {
	Name string                 `json:"name"`
	Sets []ParameterSetMetadata `json:"sets"`
}
type ParameterSetMetadata struct {
	Name       string              `json:"name"`
	Default    bool                `json:"default"`
	Parameters []ParameterMetadata `json:"parameters"`
}
type ParameterMetadata struct {
	Name         string `json:"name"`
	Position     int    `json:"position"`
	Mandatory    bool   `json:"mandatory"`
	FromPipeline bool   `json:"fromPipeline"`
	FromProperty bool   `json:"fromProperty"`
	Kind         string `json:"kind"`
}

// Project prepares Go-side input for the native differential runner. It makes
// no allow decision. Errors, including projection panics, are fixed Denials.
func Project(src []byte, ctx context.Context) (result *Projection, err error) {
	defer func() {
		if err != nil {
			result = nil
		}
	}()
	defer recoverDenial(&err)
	b := &budget{ctx: ctx, now: time.Now}
	tree := parse(src, b)
	offsets := make([]int, len(src)+1)
	units := 0
	for i := 0; i < len(src); {
		b.check()
		r, n := utf8.DecodeRune(src[i:])
		offsets[i] = units
		units++
		if r > 0xffff {
			units++
		}
		i += n
		offsets[i] = units
	}
	p := projector{offsets: offsets, b: b, result: &Projection{Tokens: []Token{}, ParseErrors: []ProjectionError{}, Bindings: []ProjectedBinding{}, Metadata: []CommandMetadata{}, Unsupported: []string{}}}
	for _, token := range tree.Tokens {
		b.check()
		token.Span = p.span(token.Span)
		token.Value, token.Quote = "", ""
		p.result.Tokens = append(p.result.Tokens, token)
	}
	p.result.Statements = p.script(tree.Script)
	for _, role := range roleTable {
		b.check()
		set := ParameterSetMetadata{Name: "safe-subset", Parameters: []ParameterMetadata{}}
		for _, param := range role.parameters {
			set.Parameters = append(set.Parameters, ParameterMetadata{Name: param.name, Position: param.position, Kind: param.kind, FromPipeline: param.name == "Value"})
		}
		sort.Slice(set.Parameters, func(i, j int) bool { return set.Parameters[i].Name < set.Parameters[j].Name })
		p.result.Metadata = append(p.result.Metadata, CommandMetadata{Name: role.name, Sets: []ParameterSetMetadata{set}})
	}
	sort.Slice(p.result.Bindings, func(i, j int) bool { return p.result.Bindings[i].Span.Start < p.result.Bindings[j].Span.Start })
	sort.Slice(p.result.Metadata, func(i, j int) bool { return p.result.Metadata[i].Name < p.result.Metadata[j].Name })
	b.check()
	return p.result, nil
}

type projector struct {
	offsets []int
	b       *budget
	result  *Projection
}

func (p *projector) span(s Span) Span { p.b.check(); return Span{p.offsets[s.Start], p.offsets[s.End]} }
func (p *projector) word(w Word) Element {
	kind, quote := "literal", "bare"
	switch w.Quote {
	case "'":
		quote = "single"
	case "\"":
		quote = "double"
	case "parameter":
		kind = "parameter"
		quote = ""
	}
	return Element{Kind: kind, Value: w.Value, Quote: quote, Colon: w.Colon, Span: p.span(w.Span), Statements: []ProjectedPipeline{}}
}
func (p *projector) script(script Script) []ProjectedPipeline {
	out := []ProjectedPipeline{}
	for _, pipe := range script.Pipelines {
		p.b.check()
		projected := ProjectedPipeline{Span: p.span(pipe.Span), Commands: []ProjectedCommand{}, Edges: []Edge{}}
		for i, c := range pipe.Commands {
			p.b.check()
			cmd := ProjectedCommand{Name: c.Name.Value, InvocationOperator: "none", Span: p.span(c.Span), Elements: []Element{p.word(c.Name)}, Redirects: []ProjectedRedirect{}}
			for _, arg := range c.Arguments {
				p.b.check()
				if arg.Word != nil {
					cmd.Elements = append(cmd.Elements, p.word(*arg.Word))
				} else {
					cmd.Elements = append(cmd.Elements, Element{Kind: "block", Span: p.span(arg.Span), Statements: p.script(*arg.Block)})
				}
			}
			for _, r := range c.Redirects {
				p.b.check()
				redir := ProjectedRedirect{Stream: r.Stream, Append: r.Append, Merge: r.Merge, Span: p.span(r.Span)}
				if r.Target != nil {
					target := p.word(*r.Target)
					redir.Target = &target
				}
				cmd.Redirects = append(cmd.Redirects, redir)
			}
			projected.Commands = append(projected.Commands, cmd)
			if i > 0 {
				projected.Edges = append(projected.Edges, Edge{i - 1, i})
			}
			p.result.Bindings = append(p.result.Bindings, p.binding(c))
		}
		out = append(out, projected)
	}
	return out
}
func (p *projector) binding(c Command) (result ProjectedBinding) {
	result = ProjectedBinding{Span: p.span(c.Span), Parameters: []BoundParameter{}, Exceptions: []string{}}
	defer func() {
		if v := recover(); v != nil {
			if reason, ok := v.(rejection); ok && (string(reason) == ReasonBinding || string(reason) == ReasonCommand) {
				result.Exceptions = append(result.Exceptions, string(reason))
			} else {
				panic(v)
			}
		}
	}()
	bound := bind(c, p.b)
	for _, arg := range bound.arguments {
		p.b.check()
		span := arg.argument.Span
		result.Parameters = append(result.Parameters, BoundParameter{Name: arg.parameter.name, Positional: arg.positional, Span: p.span(span)})
	}
	sort.Slice(result.Parameters, func(i, j int) bool {
		return strings.ToLower(result.Parameters[i].Name) < strings.ToLower(result.Parameters[j].Name)
	})
	return result
}
