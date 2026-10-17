package policy

import (
	"maps"
	"path"
	"regexp"
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
				if !printer && a.literalDepth < 4 {
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

// Unextracted source retains the Bash raw recursive-search witness. Complete
// literals use their real search output roles instead, preserving names/count
// controls. Token boundaries can separate option dashes from their letters.
var interpreterRecursiveGrep = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:grep|egrep|fgrep)\s+(?:[^;|]*\s)?(?:-\s*[a-z]*r[a-z]*|-\s*-\s*(?:dereference\s*-\s*)?recursive)(?:[^a-z0-9_]|$)`)

func unextractedRecursiveGrep(tokens []interpreterToken) bool {
	var residual strings.Builder
	for _, token := range tokens {
		if !token.literal && !token.witness && !token.opaque && !token.regexCode {
			residual.WriteString(token.text)
		}
		residual.WriteByte(' ')
	}
	return interpreterRecursiveGrep.MatchString(residual.String())
}

// Executable interpreter bodies have environment and literal-command roles in
// addition to file literals. Reader programs such as sed do not execute these
// strings and continue to use the file-only classifier.
func (a *analyzer) executableInterpreterProtected(code, cwd, name string) bool {
	// Count decoded literals against the existing 256-word analysis budget,
	// retaining the scanner's separator and record-length ceilings. Faster Go
	// analysis cannot certify unbounded literal work in any input adapter.
	if len(code) > 1<<20 || strings.Count(code, ";")+strings.Count(code, "|") > 128 {
		return true
	}
	tokens := interpreterBodyTokens(code, name, a.regexBody)
	literals := 0
	for _, token := range tokens {
		if token.indeterminate || a.expired() {
			a.reason = roles.Indeterminate
			return true
		}
		// The retained Bash search gate also denies raw recursive-grep text
		// inside inert regex data. Keep that conservative parity witness;
		// opacity only prevents treating its contents as nested launch code.
		if token.opaque && interpreterRecursiveGrep.MatchString(token.text) {
			return true
		}
		for _, expression := range token.expressions {
			literals++
			if a.literalDepth >= 4 || literals > 256 || len(expression) > 8192 {
				return true
			}
			probe := a.literalChild(cwd)
			if probe.executableInterpreterProtected(expression, cwd, name) {
				return true
			}
		}
		if token.regexCode {
			if a.literalDepth >= 4 {
				return true
			}
			// A regex body is not opaque when it can interpolate code. Scan
			// it under the existing child-depth/deadline limits, without
			// treating interpolation's # as a source comment. No regex runs.
			end := strings.LastIndexByte(token.text, '/')
			probe := a.literalChild(cwd)
			probe.regexBody = true
			if probe.executableInterpreterProtected(token.text[1:end], cwd, name) {
				return true
			}
		}
		// Numeric data words consume work too, without certifying them as
		// string argv elements for the precise launch recognizers.
		numeric := token.text != "" && token.text[0] >= '0' && token.text[0] <= '9'
		if token.literal || token.witness || numeric {
			literals++
			if literals > 256 || len(token.text) > 8192 {
				return true
			}
		}
	}
	if environmentCode(code) || unextractedRecursiveGrep(tokens) {
		return true
	}
	for _, value := range sourceLiterals(code) {
		if a.expired() {
			a.reason = roles.Indeterminate
			return true
		}
		if a.literalPrinter(value, cwd) {
			return true
		}
	}
	// Match the Bash guard's broad literal fallback before the precise argv
	// signatures. Whitespace-bearing literals receive full child classification
	// even when interpolation prevents static argv certification or their API
	// is unfamiliar. Static argv elements remain separate tokens.
	for _, token := range tokens {
		if a.expired() {
			a.reason = roles.Indeterminate
			return true
		}
		if !token.literal && !token.witness {
			continue
		}
		value := token.text
		if a.interpreterNameProtected(value, cwd) {
			return true
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 1 {
			// A standalone argv element is not an incomplete shell launcher.
			// Keep positive single-word printer roles without denying public
			// arrays merely because they contain "sh", "timeout" or "parallel".
			if a.literalPrinter(value, cwd) {
				return true
			}
			continue
		}
		if a.literalFallbackProtected(value, cwd) {
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
	probe.literalFallback = !executable
	probe.command(words, probe.literalDepth, cwd, false)
	if executable {
		return probe.literalExecutionProtected(strings.Join(words, " "))
	}
	return probe.reason != "" && probe.reason != roles.Indeterminate && !probe.structuralUncertain
}

// Every fallback command reaches the real dispatcher, without a separate role
// registry. Unknown prose is not an argv-launch slot and cannot acquire a role
// from a later word or unresolved interpolation. Invalid shell text can still
// supply a positive command witness, such as a Perl pipe literal ending in '|'.
func (a *analyzer) literalFallbackProtected(source, cwd string) bool {
	if a.literalDepth >= 4 {
		return true
	}
	probe := a.literalChild(cwd)
	probe.literalFallback = true
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		probe.command(strings.Fields(source), probe.literalDepth, cwd, false)
	} else {
		// Preserve declarations, sequential cwd and producer/consumer roles.
		// The statement classifier keeps unidentified prose operands literal;
		// modeled launches and their children retain normal shell analysis.
		probe.stmts(file.Stmts, probe.literalDepth, cwd)
	}
	return probe.reason != "" || probe.structuralUncertain
}

// An identified shell-string launch is shell source, not a one-word argv.
// Reuse the complete AST policy, including child roles, cwd flow and limits.
// Arbitrary prose must first pass the shared literal command-role classifier.
func (a *analyzer) literalShellProtected(source, cwd string) bool {
	if a.literalDepth >= 4 {
		return true
	}
	probe := a.literalChild(cwd)
	probe.fragmentAt(source, probe.literalDepth, cwd)
	return probe.literalExecutionProtected(source)
}

func (a *analyzer) literalChild(cwd string) *analyzer {
	// Initialize on the parent before copying: a child must not create a
	// private cache for each repeated literal. Only metadata proofs are shared;
	// mutable command/environment state remains scoped to the child.
	if a.interpreterNames == nil {
		a.interpreterNames = make(map[interpreterName]bool)
	}
	if a.configWrites == nil {
		a.configWrites = make(map[[4]string]bool)
	}
	return &analyzer{protected: a.protected, cwd: cwd, home: a.home,
		deadline: a.deadline, now: a.now, metadata: a.pathMetadata(),
		configWrites: a.configWrites, configWriteCheck: a.configWriteCheck,
		credentialConfigs: slices.Clone(a.credentialConfigs), env: maps.Clone(a.env),
		interpreterNames: a.interpreterNames, literalDepth: a.literalDepth + 1}
}

func (a *analyzer) literalExecutionProtected(source string) bool {
	return a.reason != "" || a.structuralUncertain || a.uncertain && (witness(source) || riskyRole(source) || contentSyntax(source))
}
