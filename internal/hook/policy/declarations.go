package policy

import (
	"regexp"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

var declarationName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Configured paths use the same bounded scalar expansion as interpreter stdin:
// HOME and static variables expand without execution, splitting or globbing.
// An unresolved declaration is not an empty assignment that erases protection.
func (a *analyzer) assignmentLiteral(key string, word *syntax.Word, cwd string) string {
	if !optionIn("KUBECONFIG AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE XDG_CONFIG_HOME GH_CONFIG_DIR", key) || word == nil {
		return literal(word)
	}
	value, known := a.expandInterpreterStdin(word, false, cwd)
	if !known {
		a.reason = roles.Indeterminate
		return ""
	}
	return value
}

func declarationCommand(name string) bool {
	return optionIn("export declare typeset", name)
}

// declarationOperand recognizes assignment operands only for declaration
// builtins. Ordinary command arguments containing '=' remain data.
func declarationOperand(operand string) (key, value string, appendValue, ok bool) {
	key, value, ok = strings.Cut(operand, "=")
	if !ok {
		return "", "", false, false
	}
	appendValue = strings.HasSuffix(key, "+")
	if appendValue {
		key = strings.TrimSuffix(key, "+")
	}
	return key, value, appendValue, declarationName.MatchString(key)
}

// declarationOperands follows transparent prefixes on expanded argv while
// retaining the original AST word for every declaration operand.
func declarationOperands(operands []expandedOperand) []expandedOperand {
	for len(operands) > 1 {
		name := operands[0].value
		if name != "command" && name != "builtin" {
			break
		}
		i := 1
		for i < len(operands) {
			option := operands[i].value
			if option == "--" {
				i++
				break
			}
			if name != "command" || option != "-p" {
				break
			}
			i++
		}
		if i >= len(operands) || !operands[i].known || strings.HasPrefix(operands[i].value, "-") {
			break
		}
		operands = operands[i:]
	}
	return operands
}

// declarationWords preserves source uncertainty during argv expansion. Static
// expansion cannot certify a sensitive command-text assignment as literal.
func (a *analyzer) declarationWords(words []*syntax.Word, depth int, cwd string) string {
	for _, word := range words {
		value := literal(word)
		prefix := value
		if prefix == "" {
			prefix = declarationPrefix(word.Parts)
		}
		if key, _, _, ok := declarationOperand(prefix); ok {
			if key == "CDPATH" {
				a.cdpath = true
				cwd = ""
			}
			if value == "" {
				a.hookAssignment(key, "", depth, cwd)
				a.arithmeticWriteUnknown(key)
			}
		} else if value == "" && declarationExpansion(word) {
			a.indirect = true // Expanded names remain indirect even if currently static.
			a.arithmeticOpaque = true
		}
	}
	return cwd
}

// declarationAssignments shares direct assignment and append checks with the
// declaration AST path, after transparent wrappers and quoting are normalized.
func (a *analyzer) declarationAssignments(args []string, depth int, cwd string) string {
	for _, operand := range args {
		if key, value, appendValue, ok := declarationOperand(operand); ok {
			if key == "CDPATH" {
				a.cdpath = true
				cwd = ""
			}
			if appendValue {
				a.hookAppend(key, value, depth, cwd)
			} else {
				a.hookAssignment(key, value, depth, cwd)
			}
		}
	}
	return cwd
}

// declarationExpansion distinguishes an expanded name from an empty literal.
func declarationExpansion(word *syntax.Word) bool {
	expanded := false
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case nil, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		default:
			expanded = true
		}
		return !expanded
	})
	return expanded
}

// declarationPrefix decodes only the leading literal parts of an operand. It
// identifies EDITOR= even in "EDITOR=$value", without evaluating the value.
func declarationPrefix(parts []syntax.WordPart) string {
	var prefix strings.Builder
	var visit func([]syntax.WordPart) bool
	visit = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch n := part.(type) {
			case *syntax.Lit, *syntax.SglQuoted:
				prefix.WriteString(literal(&syntax.Word{Parts: []syntax.WordPart{part}}))
			case *syntax.DblQuoted:
				if !visit(n.Parts) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	visit(parts)
	return prefix.String()
}
