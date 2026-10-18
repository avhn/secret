package policy

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// Inside double-quoted parameter words and array indices, single quotes are
// literal characters, not a barrier to command substitution. The parser models
// them as SglQuoted, so reparse only those expansion-bearing parts as document
// words. Document never executes code or treats the surrounding text as commands.
func (a *analyzer) walkQuotedParameter(node syntax.Node, depth int, cwd string) {
	syntax.Walk(node, func(node syntax.Node) bool {
		if a.reason != "" {
			return false
		}
		switch n := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			// Their inner commands start a new quoting context and are visited
			// by walkNode; do not reparse their inert quoted arguments here.
			return false
		case *syntax.Word:
			quoted := false
			for _, part := range n.Parts {
				_, single := part.(*syntax.SglQuoted)
				quoted = quoted || single
			}
			if !quoted {
				return true
			}
			// Reparse the whole word: a substitution's own quotes may split
			// it across multiple incorrectly single-quoted parser parts.
			source := a.raw(n)
			if !strings.Contains(source, "$(") && !strings.ContainsRune(source, '`') {
				return false
			}
			if depth > 4 || len(source) > 40<<10 || a.expired() {
				a.reason = roles.Indeterminate
				return false
			}
			word, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Document(strings.NewReader(source))
			if err != nil || !bashFraming(word) {
				a.reason = roles.Indeterminate
				return false
			}
			a.walkQuotedParameter(word, depth+1, cwd)
			a.walkNode(word, depth+1, cwd)
			return false
		}
		return true
	})
}

func (a *analyzer) walkDoubleQuotedParameters(quoted *syntax.DblQuoted, depth int, cwd string) {
	for _, part := range quoted.Parts {
		if parameter, ok := part.(*syntax.ParamExp); ok {
			a.walkQuotedParameter(parameter, depth, cwd)
		}
	}
}

// expandedOperand keeps role classification aligned with the actual argv fields,
// including brace-expanded option words and unresolved operand placeholders.
type expandedOperand struct {
	value  string
	source *syntax.Word
	known  bool
}

type literalField struct {
	value, pattern string
	quoted         bool
}

var ifsIdentifier = regexp.MustCompile(`(^|[^a-zA-Z0-9_])IFS([^a-zA-Z0-9_]|$)`)

// Only syntax that can modify IFS disqualifies default whitespace splitting.
// Comments and ordinary literal arguments do not change the shell's state.
func (a *analyzer) noteIFS(file *syntax.File, source string) {
	var empty *syntax.Assign
	for _, stmt := range file.Stmts {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 {
			for _, assign := range call.Assigns {
				if assign.Name != nil && assign.Name.Value == "IFS" && !assign.Append && assign.Array == nil && assign.Index == nil && emptyLiteralWord(assign.Value) {
					empty = assign
				}
			}
		}
	}
	changes := 0
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Assign:
			if n.Name != nil && n.Name.Value == "IFS" {
				changes++
				if n != empty {
					empty = nil
				}
			}
		case *syntax.WordIter:
			if n.Name != nil && n.Name.Value == "IFS" {
				changes++
			}
		case *syntax.ParamExp:
			if n.Param != nil && n.Param.Value == "IFS" && n.Exp != nil && (n.Exp.Op == syntax.AssignUnset || n.Exp.Op == syntax.AssignUnsetOrNull) {
				changes++
			}
		case *syntax.CallExpr:
			call := unwrapCall(n)
			if len(call.Args) == 0 {
				break
			}
			name := literal(call.Args[0])
			if name == "printf" {
				assigns := false
				for _, arg := range call.Args[1:] {
					option := literal(arg)
					if option == "--" || !strings.HasPrefix(option, "-") {
						break
					}
					assigns = assigns || strings.Contains(option[1:], "v")
				}
				if !assigns {
					break
				}
			}
			switch name {
			case "read", "mapfile", "readarray", "unset", "getopts", "let", "printf":
				for _, arg := range call.Args[1:] {
					value := literal(arg)
					if name == "printf" {
						value = strings.TrimPrefix(value, "-v")
					}
					if ifsIdentifier.MatchString(value) {
						changes++
						break
					}
				}
			}
		case *syntax.ArithmCmd, *syntax.CStyleLoop:
			found := false
			syntax.Walk(node, func(child syntax.Node) bool {
				if word, ok := child.(*syntax.Word); ok && word.Lit() == "IFS" {
					found = true
				}
				return !found
			})
			if found {
				changes++
			}
		}
		return true
	})
	if changes > 0 {
		a.ifsSource = source
		a.ifsModified = true
		// Certify empty IFS from its syntax as well as its reached assignment.
		// This also covers argv shells, which have no outer source to rescan.
		a.ifsEmpty = changes == 1 && empty != nil && !indirectStaticAssignment(source)
	}
}

// A missing scalar value or literal empty quotes are known empty assignments,
// unlike substitutions and array assignments whose literal value is also "".
func emptyLiteralWord(word *syntax.Word) bool {
	if word == nil {
		return true
	}
	empty := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch n := node.(type) {
		case nil, *syntax.Word, *syntax.DblQuoted:
		case *syntax.Lit:
			empty = empty && n.Value == ""
		case *syntax.SglQuoted:
			empty = empty && n.Value == ""
		default:
			empty = false
		}
		return empty
	})
	return empty
}

// Only unquoted parameter values split fields. Literal and quoted whitespace
// stays in its field, and a trailing delimiter separates a later word part.
// Non-whitespace IFS grammars remain indeterminate rather than certifying a
// single executable name that may actually hide a reader and its operands.
func (a *analyzer) appendLiteralFields(fields []literalField, value, pattern string, quoted, split bool) ([]literalField, bool) {
	if len(fields) == 0 {
		fields = append(fields, literalField{})
	}
	appendValue := func(value, pattern string) {
		last := &fields[len(fields)-1]
		last.value += value
		last.pattern += pattern
		last.quoted = last.quoted || quoted
	}
	if !split {
		appendValue(value, pattern)
		return fields, true
	}
	ifs := " \t\n"
	if _, assigned := a.env["IFS"]; assigned || a.ifsModified {
		var known bool
		ifs, known = a.staticVariable("IFS")
		if !known {
			a.reason = roles.Indeterminate
			return nil, false
		}
	}
	if strings.Trim(ifs, " \t\n") != "" && strings.ContainsAny(value, ifs) {
		a.reason = roles.Indeterminate
		return nil, false
	}
	for value != "" {
		index := strings.IndexAny(value, ifs)
		if index < 0 {
			appendValue(value, value)
			break
		}
		appendValue(value[:index], value[:index])
		value = strings.TrimLeft(value[index:], ifs)
		last := fields[len(fields)-1]
		if last.value != "" || last.quoted {
			if len(fields) >= 256 {
				a.reason = roles.Indeterminate
				return nil, false
			}
			fields = append(fields, literalField{})
		}
	}
	return fields, true
}

// braceWordCount bounds alternatives before the lazy AST-only expansion. Sequence
// expansion remains unsupported, matching the existing policy's grammar budget.
func braceWordCount(word *syntax.Word) (int, bool) {
	return boundedBraceCount(word, false)
}

// A bounded sequence remains unsupported for reader certification, but its
// size must still be checked before echo/printf can discard word uncertainty.
func boundedBraceCount(word *syntax.Word, sequences bool) (int, bool) {
	count := 1
	for _, part := range word.Parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		if brace.Sequence {
			if !sequences {
				return 0, false
			}
			n, ok := braceSequenceCount(brace)
			if !ok || count*n > 64 {
				return 0, false
			}
			count *= n
			continue
		}
		if len(brace.Elems) > 64 {
			return 0, false
		}
		alternatives := 0
		for _, elem := range brace.Elems {
			n, ok := boundedBraceCount(elem, sequences)
			if !ok || alternatives+n > 64 {
				return 0, false
			}
			alternatives += n
		}
		count *= alternatives
		if count > 64 {
			return 0, false
		}
	}
	return count, true
}

func braceSequenceCount(brace *syntax.BraceExp) (int, bool) {
	if len(brace.Elems) < 2 || len(brace.Elems) > 3 {
		return 0, false
	}
	values := []int64{0, 0, 1}
	for i, elem := range brace.Elems {
		text := elem.Lit()
		if len(text) == 0 || len(text) > 6 {
			return 0, false
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			if i >= 2 || len(text) != 1 || !(text[0] >= 'a' && text[0] <= 'z' || text[0] >= 'A' && text[0] <= 'Z') {
				return 0, false
			}
			n = int64(text[0])
		}
		values[i] = n
	}
	span, step := values[1]-values[0], values[2]
	if span < 0 {
		span = -span
	}
	if step < 0 {
		step = -step
	}
	if step == 0 {
		step = 1
	}
	n := span/step + 1
	return int(n), n <= 64
}
