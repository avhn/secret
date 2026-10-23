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

// Expansion-bearing expression contexts share the normal substitution walker.
// Stored arithmetic values and opaque parser patterns need an extra syntax pass.
func (a *analyzer) walkExpansionSyntax(node syntax.Node, depth int, cwd string) {
	if a.reason != "" || node == nil {
		return
	}
	switch n := node.(type) {
	case *syntax.ExtGlob:
		a.walkExtglob(n, depth, cwd)
	case *syntax.ArithmExp:
		a.reevaluatedArithmetic(n.X)
	case *syntax.ArithmCmd:
		a.reevaluatedArithmetic(n.X)
	case *syntax.CStyleLoop, *syntax.LetClause:
		a.reevaluatedArithmetic(node)
	case *syntax.ParamExp:
		if n.Repl != nil && n.Repl.Orig != nil {
			// Process substitutions in replacement patterns may also remain
			// unquoted literal parts rather than exposed expansion nodes.
			for _, part := range n.Repl.Orig.Parts {
				if lit, ok := part.(*syntax.Lit); ok && (strings.Contains(lit.Value, "<(") || strings.Contains(lit.Value, ">(")) {
					a.reason = roles.Indeterminate
				}
			}
		}
		if n.Index != nil {
			a.reevaluatedArithmetic(n.Index)
		}
		if n.Slice != nil {
			if n.Slice.Offset != nil {
				a.reevaluatedArithmetic(n.Slice.Offset)
			}
			if n.Slice.Length != nil {
				a.reevaluatedArithmetic(n.Slice.Length)
			}
		}
	case *syntax.Assign:
		if n.Name != nil && a.integerVariables[n.Name.Value] {
			if n.Value != nil {
				a.reevaluatedArithmetic(n.Value)
			}
			if n.Array != nil {
				a.reevaluatedArithmetic(n.Array)
			}
		}
		if n.Index != nil {
			a.reevaluatedArithmetic(n.Index)
		} else if n.Name != nil && n.Value != nil && n.Array == nil {
			value, known := a.arithmeticWordValue(n.Value)
			if !known {
				a.noteArithmeticUnknown(n.Name.Value)
			} else if !n.Append {
				a.noteArithmeticValue(n.Name.Value, value)
			} else if literal(n.Value) == "" {
				// Literal appends were already recorded before env was merged.
				a.noteArithmeticAppend(n.Name.Value, value)
			}
		}
	case *syntax.ArrayElem:
		if n.Index != nil {
			a.reevaluatedArithmetic(n.Index)
		}
	case *syntax.WordIter:
		if n.Name != nil {
			if len(n.Items) == 0 {
				a.noteArithmeticUnknown(n.Name.Value)
			}
			for _, item := range n.Items {
				value, known := a.arithmeticWordValue(item)
				if !known {
					a.noteArithmeticUnknown(n.Name.Value)
					break
				}
				a.noteArithmeticValue(n.Name.Value, value)
			}
		}
	case *syntax.DeclClause:
		a.reevaluatedDeclaration(n)
	case *syntax.BinaryTest:
		switch n.Op {
		case syntax.TsEql, syntax.TsNeq, syntax.TsLeq, syntax.TsGeq, syntax.TsLss, syntax.TsGtr:
			a.reevaluatedArithmetic(n)
		}
	}
}

// Extglob patterns are opaque literals in the parser, including substitutions
// that execute in [[ ]], case patterns and parameter replacement patterns.
// Document reparses expansion syntax without turning pattern alternatives into
// command pipelines. Unsupported quoting or malformed inner code cannot certify
// an allow; the normal walker classifies every recovered substitution.
func (a *analyzer) walkExtglob(pattern *syntax.ExtGlob, depth int, cwd string) {
	if pattern.Pattern == nil {
		a.reason = roles.Indeterminate
		return
	}
	source := pattern.Pattern.Value
	// Document does not expose process substitutions as nodes. Do not let
	// their opaque syntax become an allow proof inside a pattern either.
	if strings.Contains(source, "<(") || strings.Contains(source, ">(") {
		a.reason = roles.Indeterminate
		return
	}
	if !strings.ContainsAny(source, "$`") {
		return
	}
	if depth > 4 || len(source) > 40<<10 || a.expired() {
		a.reason = roles.Indeterminate
		return
	}
	word, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Document(strings.NewReader(source))
	if err != nil || !bashFraming(word) {
		a.reason = roles.Indeterminate
		return
	}
	a.walkNode(word, depth+1, cwd)
}

var arithmeticIdentifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

func activeArithmeticSyntax(value string) bool {
	return strings.ContainsAny(value, "$`")
}

// A scalar expansion cannot borrow env's empty sentinel or the first loop item
// when several values are possible. Keep that uncertainty for arithmetic only;
// ordinary quoted data remains inert.
func (a *analyzer) arithmeticWordValue(word *syntax.Word) (string, bool) {
	known := true
	syntax.Walk(word, func(node syntax.Node) bool {
		if parameter, ok := node.(*syntax.ParamExp); ok && parameter.Param != nil {
			if values, assigned := a.arithmeticValues[parameter.Param.Value]; assigned && len(values) != 1 {
				known = false
			}
		}
		return known
	})
	if !known {
		return "", false
	}
	return a.declarationReevaluationValue(word)
}

// Arithmetic needs possible values, not env's empty uncertainty sentinel or
// loopVars' first-item proof. Retain alternatives monotonically across branches
// and reassignments; nil marks a binding whose alternatives exceeded the budget
// or could not be resolved. Neither an overwrite nor loop exit can erase a deny.
func (a *analyzer) noteArithmeticUnknown(name string) {
	if a.arithmeticValues == nil {
		a.arithmeticValues = make(map[string][]string)
	}
	a.arithmeticValues[name] = nil
}

func (a *analyzer) noteArithmeticValue(name, value string) {
	values, assigned := a.arithmeticValues[name]
	if assigned && values == nil {
		return
	}
	bytes := len(value)
	for _, previous := range values {
		if previous == value {
			return
		}
		bytes += len(previous)
	}
	if len(values) >= 64 || bytes > 40<<10 {
		a.noteArithmeticUnknown(name)
		return
	}
	if a.arithmeticValues == nil {
		a.arithmeticValues = make(map[string][]string)
	}
	a.arithmeticValues[name] = append(values, value)
}

// Appending can create active syntax across word boundaries. Combine the suffix
// with every possible prefix before hookAssignment loses env's prior value.
func (a *analyzer) noteArithmeticAppend(name, suffix string) {
	values, assigned := a.arithmeticValues[name]
	if !assigned {
		values = []string{a.env[name]}
	}
	for _, previous := range values {
		a.noteArithmeticValue(name, previous+suffix)
	}
}

// Arithmetic recursively evaluates expanded operands, including array subscripts
// in the resulting text. No expansion's output can certify inert arithmetic, even
// if its command or currently known value looks harmless. Deny those operands
// without evaluation, and retain bounded checks of stored plain variable names.
func (a *analyzer) reevaluatedArithmetic(node syntax.Node) {
	seen := make(map[string]bool)
	var active func(string, int) bool
	active = func(value string, depth int) bool {
		if depth > 0 && activeArithmeticSyntax(value) {
			return true
		}
		for _, name := range arithmeticIdentifier.FindAllString(value, -1) {
			if seen[name] {
				continue
			}
			values, known := a.arithmeticValues[name]
			if !known {
				stored, ok := a.loopVars[name]
				if !ok {
					stored, ok = a.env[name]
				}
				if !ok {
					continue
				}
				values = []string{stored}
			}
			if values == nil || depth >= 4 || len(seen) >= 256 || a.expired() {
				return true
			}
			seen[name] = true
			for _, stored := range values {
				if active(stored, depth+1) {
					return true
				}
			}
		}
		return false
	}
	syntax.Walk(node, func(node syntax.Node) bool {
		if a.reason != "" {
			return false
		}
		switch n := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp:
			a.reason = roles.Indeterminate
		case *syntax.ParamExp:
			// The parser also represents bare arr[0] as a parameter node,
			// without a dollar position. Its literal subscript stays arithmetic.
			if n.Dollar.IsValid() {
				a.reason = roles.Indeterminate
			}
		case *syntax.Lit:
			if activeArithmeticSyntax(n.Value) || active(n.Value, 0) {
				a.reason = roles.Indeterminate
			}
		case *syntax.SglQuoted:
			// let and integer declarations can preserve expansion spelling as
			// quoted text until the arithmetic evaluation pass.
			if activeArithmeticSyntax(n.Value) || active(n.Value, 0) {
				a.reason = roles.Indeterminate
			}
		}
		return a.reason == ""
	})
}

// Retain possible integer attributes monotonically, like stored arithmetic
// alternatives: a conditional declaration cannot be erased by another branch.
func (a *analyzer) noteIntegerVariable(name string) {
	if a.integerVariables == nil {
		a.integerVariables = make(map[string]bool)
	}
	a.integerVariables[name] = true
}

// A quoted compound-assignment string is reinterpreted by array declarations.
// Real array AST values retain their element quoting and are walked normally.
func (a *analyzer) reevaluatedDeclaration(decl *syntax.DeclClause) {
	array, integer := false, false
	for _, assign := range decl.Args {
		if integer && assign.Name != nil {
			a.noteIntegerVariable(assign.Name.Value)
		}
		if assign.Array != nil {
			if integer {
				a.reevaluatedArithmetic(assign.Array)
			}
			continue
		}
		if assign.Value == nil {
			continue
		}
		if assign.Name != nil && !array && !integer {
			continue
		}
		value, known := a.declarationReevaluationValue(assign.Value)
		if a.reason != "" {
			return
		}
		if assign.Name == nil {
			if known && strings.HasPrefix(value, "-") {
				array = array || strings.ContainsAny(value[1:], "aA")
				integer = integer || strings.ContainsRune(value[1:], 'i')
				continue
			}
			if known {
				if integer && declarationName.MatchString(value) {
					a.noteIntegerVariable(value)
					continue
				}
				var name string
				name, value, _, known = declarationOperand(value)
				if integer && known {
					a.noteIntegerVariable(name)
				}
			}
		}
		if !known {
			if array || integer {
				a.reevaluatedArithmetic(assign.Value)
			}
			continue
		}
		if integer || array && strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
			if activeArithmeticSyntax(value) {
				a.reason = roles.Indeterminate
				return
			}
			if integer {
				a.reevaluatedArithmetic(assign.Value)
			} else {
				// Non-integer compound assignments reinterpret the normalized
				// shell text, not the scalar expansion that supplied that text.
				a.reevaluatedArithmetic(&syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: value}}})
			}
		}
	}
}

// Normalize declaration operands as scalars, without field splitting, globbing
// or executing substitutions. Stored parameter text is used only to detect a
// deny: staticVariable intentionally rejects the active syntax needed here.
// Expansion is one pass, so quotes and dollar signs inside a value stay data
// until the caller checks whether the declaration reinterprets that value.
func (a *analyzer) declarationReevaluationValue(word *syntax.Word) (string, bool) {
	var value strings.Builder
	steps := 0
	var visit func([]syntax.WordPart, bool, int) bool
	visit = func(parts []syntax.WordPart, quoted bool, depth int) bool {
		for _, part := range parts {
			steps++
			if depth > 4 || steps > 256 || a.expired() {
				a.reason = roles.Indeterminate
				return false
			}
			var piece string
			switch n := part.(type) {
			case *syntax.Lit:
				if quoted {
					piece = doubleLiteral(n.Value)
				} else {
					var decoded strings.Builder
					for i := 0; i < len(n.Value); i++ {
						if n.Value[i] == '\\' && i+1 < len(n.Value) {
							i++
							if n.Value[i] == '\n' {
								continue
							}
						}
						decoded.WriteByte(n.Value[i])
					}
					piece = decoded.String()
				}
			case *syntax.SglQuoted:
				piece = n.Value
				if n.Dollar {
					var ok bool
					piece, ok = ansiLiteral(piece)
					if !ok {
						return false
					}
				}
			case *syntax.DblQuoted:
				if !visit(n.Parts, true, depth+1) {
					return false
				}
				continue
			case *syntax.ParamExp:
				if n.Param == nil || n.Exp != nil || n.Repl != nil || n.Slice != nil || n.Index != nil || n.Length || n.Excl || n.Width || n.Names != 0 {
					return false
				}
				var ok bool
				piece, ok = a.loopVars[n.Param.Value]
				if !ok {
					piece, ok = a.env[n.Param.Value]
				}
				if !ok {
					return false
				}
			default:
				return false
			}
			if value.Len()+len(piece) > 40<<10 {
				a.reason = roles.Indeterminate
				return false
			}
			value.WriteString(piece)
		}
		return true
	}
	known := visit(word.Parts, false, 0)
	return value.String(), known
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
