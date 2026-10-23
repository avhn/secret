package policy

import (
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// A nameref can acquire an integer target after its declaration. Follow all
// possible targets without treating an unresolved reference as an inert scalar.
func (a *analyzer) possibleInteger(name string) bool {
	seen := make(map[string]bool)
	var visit func(string) bool
	visit = func(name string) bool {
		name, _, _ = strings.Cut(name, "[")
		if a.integerVariables[name] {
			return true
		}
		if seen[name] {
			return false
		}
		if len(seen) >= 64 || a.expired() {
			return true
		}
		seen[name] = true
		targets, reference := a.arithmeticRefs[name]
		if reference && len(targets) == 0 {
			return true
		}
		for _, target := range targets {
			if visit(target) {
				return true
			}
		}
		return false
	}
	return visit(name)
}

func (a *analyzer) arithmeticReference(name, target string) {
	if a.arithmeticRefs == nil {
		a.arithmeticRefs = make(map[string][]string)
	}
	a.noteArithmeticUnknown(name)
	base, _, _ := strings.Cut(target, "[")
	if !declarationName.MatchString(base) || activeArithmeticSyntax(target) {
		a.arithmeticRefs[name] = nil
		a.arithmeticOpaque = true
		return
	}
	if targets, exists := a.arithmeticRefs[name]; !exists || targets != nil {
		a.arithmeticRefs[name] = append(slices.Clone(a.arithmeticRefs[name]), target)
	}
	a.noteArithmeticUnknown(base)
}

// Writers without a certified scalar result invalidate arithmetic proofs, not
// ordinary data uses. They bind through namerefs too. Possible integer targets
// evaluate the value immediately, before any later arithmetic expression.
func (a *analyzer) arithmeticWriteUnknown(target string) {
	base, _, indexed := strings.Cut(target, "[")
	if !declarationName.MatchString(base) {
		a.arithmeticOpaque = true
		if len(a.integerVariables) != 0 || len(a.arithmeticRefs) != 0 {
			a.reason = roles.Indeterminate
		}
		return
	}
	if indexed {
		a.reevaluatedArithmetic(&syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: target}}})
	}
	a.arithmeticReferenceBinding(base)
	if a.possibleInteger(base) {
		a.reason = roles.Indeterminate
	}
	a.invalidateArithmeticWrite(base)
}

// Nameref array subscripts are arithmetic contexts on the eventual bind, even
// when the variable receiving the value has no integer attribute.
func (a *analyzer) arithmeticReferenceBinding(name string) {
	seen := make(map[string]bool)
	var visit func(string)
	visit = func(name string) {
		if a.reason != "" {
			return
		}
		if seen[name] || len(seen) >= 64 || a.expired() {
			a.reason = roles.Indeterminate
			return
		}
		targets, reference := a.arithmeticRefs[name]
		if !reference {
			return
		}
		if len(targets) == 0 {
			a.reason = roles.Indeterminate
			return
		}
		seen[name] = true
		for _, target := range targets {
			base, index, indexed := strings.Cut(target, "[")
			if indexed {
				if !strings.HasSuffix(index, "]") {
					a.reason = roles.Indeterminate
					return
				}
				a.reevaluatedArithmetic(&syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: strings.TrimSuffix(index, "]")}}})
			}
			visit(base)
		}
		delete(seen, name)
	}
	visit(name)
}

func (a *analyzer) invalidateArithmeticWrite(base string) {
	seen := make(map[string]bool)
	var invalidate func(string)
	invalidate = func(name string) {
		name, _, _ = strings.Cut(name, "[")
		if seen[name] {
			return
		}
		seen[name] = true
		a.noteArithmeticUnknown(name)
		delete(a.env, name)
		delete(a.loopVars, name)
		if len(seen) >= 64 || a.expired() {
			a.arithmeticOpaque = true
			return
		}
		for _, target := range a.arithmeticRefs[name] {
			invalidate(target)
		}
	}
	invalidate(base)
}

func (a *analyzer) arithmeticWriter(name string, args []string) {
	switch name {
	case "declare", "typeset", "local":
		nameref := false
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") {
				nameref = nameref || strings.ContainsRune(arg[1:], 'n')
				continue
			}
			if nameref {
				key, target, _ := strings.Cut(arg, "=")
				if declarationName.MatchString(key) {
					a.arithmeticReference(key, target)
				} else {
					a.arithmeticOpaque = true
				}
			}
		}
	case "printf":
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if arg == "" {
				a.arithmeticWriteUnknown("")
			}
			if arg == "-v" && i+1 < len(args) {
				i++
				a.arithmeticWriteUnknown(args[i])
			} else if strings.HasPrefix(arg, "-v") {
				a.arithmeticWriteUnknown(arg[2:])
			} else {
				break // The format and its arguments are data, not options.
			}
		}
	case "getopts":
		if len(args) >= 2 {
			a.arithmeticWriteUnknown(args[1])
		} else {
			a.arithmeticWriteUnknown("")
		}
		a.arithmeticWriteUnknown("OPTARG")
		a.arithmeticWriteUnknown("OPTIND")
	case "read", "mapfile", "readarray":
		var targets []string
		options := true
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if options && arg == "--" {
				options = false
				continue
			}
			if options && strings.HasPrefix(arg, "-") && len(arg) > 1 {
				withValue := "dinNptua"
				if name != "read" {
					withValue = "dnOsuCc"
				}
				for j := 1; j < len(arg); j++ {
					if !strings.ContainsRune(withValue, rune(arg[j])) {
						continue
					}
					value := arg[j+1:]
					if value == "" && i+1 < len(args) {
						i++
						value = args[i]
					}
					if name == "read" && arg[j] == 'a' {
						targets = append(targets, value)
					}
					break
				}
				continue
			}
			options = false
			targets = append(targets, arg)
		}
		if len(targets) == 0 {
			target := "MAPFILE"
			if name == "read" {
				target = "REPLY"
			}
			targets = append(targets, target)
		}
		for _, target := range targets {
			a.arithmeticWriteUnknown(target)
		}
	}
}
