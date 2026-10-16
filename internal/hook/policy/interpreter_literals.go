package policy

import (
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

type interpreterName struct{ name, cwd, config string }

// Cache caller-supplied metadata decisions only for the lifetime of an analysis.
// A configured-path assignment is checked separately and cannot reuse this key.
func cachedProtection(check func(string, string) bool) func(string, string) bool {
	cache := make(map[[2]string]bool)
	return func(name, cwd string) bool {
		key := [2]string{name, cwd}
		if protected, ok := cache[key]; ok {
			return protected
		}
		protected := check(name, cwd)
		if len(cache) < 4096 {
			cache[key] = protected
		}
		return protected
	}
}

// Inspect each quote kind independently so a shell-quoted interpreter argument
// does not hide its inner language literals. This is positive-witness scanning,
// not a language evaluator; escaped and decoded stdin are checked separately.
func sourceLiterals(code string) []string {
	var values []string
	for _, quote := range []byte{'\'', '"', '`'} {
		start := -1
		for i := 0; i < len(code); i++ {
			if code[i] == '\\' {
				i++
				continue
			}
			if code[i] != quote {
				continue
			}
			if start < 0 {
				start = i + 1
			} else {
				values = append(values, code[start:i])
				start = -1
			}
		}
	}
	return values
}

// Literal command strings use the same credential roles as direct shell calls.
// Only literal words count as witnesses. Invalid language text is not shell code
// and cannot itself supply an allow or a denial through this helper.
func (a *analyzer) literalPrinter(code, cwd string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(code), "")
	if err != nil {
		return false
	}
	printer := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if printer {
			return false
		}
		switch cmd := node.(type) {
		case *syntax.CallExpr:
			var words []string
			for _, word := range cmd.Args {
				known := true
				syntax.Walk(word, func(node syntax.Node) bool {
					switch node.(type) {
					case nil, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
					default:
						known = false
					}
					return known
				})
				if !known {
					return true
				}
				words = append(words, literal(word))
			}
			if len(words) > 0 {
				name := strings.ToLower(path.Base(words[0]))
				printer = roles.PrinterReason(name, words[1:], false) != ""
				_, utility := utilityTable[name]
				if !printer && a.literalDepth < 4 && (utility || shellName(name) || optionIn("env command builtin setsid parallel", name)) {
					// Reuse the actual child-role dispatcher, but isolate command
					// state from the enclosing interpreter and outer shell.
					printer = a.literalCommandProtected(words, cwd, false)
				}
			}
		case *syntax.DeclClause:
			var args []string
			for _, assign := range cmd.Args {
				if assign.Value != nil {
					args = append(args, literal(assign.Value))
				}
			}
			printer = roles.PrinterReason(cmd.Variant.Value, args, false) != ""
		}
		return true
	})
	return printer
}

// Executable interpreter bodies have environment and literal-command roles in
// addition to file literals. Reader programs such as sed do not execute these
// strings and continue to use the file-only classifier.
func (a *analyzer) executableInterpreterProtected(code, cwd, name string) bool {
	if environmentCode(code) {
		return true
	}
	for _, value := range sourceLiterals(code) {
		if a.literalPrinter(value, cwd) {
			return true
		}
	}
	return a.interpreterArgvProtected(code, cwd, name) || a.interpreterProtected(code, cwd)
}

// Literal argv launches and shell-string witnesses share the real dispatcher,
// but cannot mutate the interpreter's surrounding shell state. An identified
// executable launch must retain uncertain child results; arbitrary prose needs
// a concrete role witness, not an incomplete launcher or recursion limit.
func (a *analyzer) literalCommandProtected(words []string, cwd string, executable bool) bool {
	if len(words) == 0 {
		return false
	}
	if a.literalDepth >= 4 {
		return executable
	}
	probe := a.literalChild(cwd)
	probe.command(words, probe.literalDepth, cwd, false)
	if executable {
		return probe.literalExecutionProtected(strings.Join(words, " "))
	}
	return probe.reason != "" && probe.reason != roles.Indeterminate && !probe.structuralUncertain
}

// An identified shell-string launch is shell source, not a one-word argv.
// Reuse the complete AST policy, including child roles, cwd flow and limits.
// Arbitrary source literals still require literalPrinter's positive witnesses.
func (a *analyzer) literalShellProtected(source, cwd string) bool {
	if a.literalDepth >= 4 {
		return true
	}
	probe := a.literalChild(cwd)
	probe.fragmentAt(source, probe.literalDepth, cwd)
	return probe.literalExecutionProtected(source)
}

func (a *analyzer) literalChild(cwd string) *analyzer {
	return &analyzer{protected: a.protected, cwd: cwd, home: a.home,
		deadline: a.deadline, metadata: a.metadata,
		credentialConfigs: slices.Clone(a.credentialConfigs), env: maps.Clone(a.env),
		interpreterNames: a.interpreterNames, literalDepth: a.literalDepth + 1}
}

func (a *analyzer) literalExecutionProtected(source string) bool {
	return a.reason != "" || a.structuralUncertain || a.uncertain && (witness(source) || riskyRole(source) || contentSyntax(source))
}
