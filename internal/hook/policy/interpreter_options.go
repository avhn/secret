package policy

import "strings"

type interpreterOptionGrammar struct {
	code, flags, numeric, values string
	longCode, longValues         string
	subcommands, terminal        string
	optional                     string
}

func interpreterOptions(name string) interpreterOptionGrammar {
	switch {
	case pythonInterpreter(name):
		return interpreterOptionGrammar{code: "c", flags: "bBdEhiIOPqRsSuvVx", values: "mWX", longValues: "--check-hash-based-pycs", terminal: "cm"}
	case name == "ruby":
		return interpreterOptionGrammar{code: "e", flags: "acdhlnpsSvwy", numeric: "0W", values: "CEFIKr", longValues: "--encoding --external-encoding --internal-encoding --backtrace-limit"}
	case name == "perl":
		return interpreterOptionGrammar{code: "eE", flags: "acdfhnpsStTuUvwWxX", numeric: "0l", values: "CFIiMm", optional: "CFi"}
	case javascriptInterpreter(name):
		grammar := interpreterOptionGrammar{code: "ep", flags: "ci", values: "r", longCode: "--eval --print", longValues: "--env-file --env-file-if-exists --require --import --loader --experimental-loader --input-type --inspect-port --title"}
		if name == "bun" {
			grammar.subcommands = "run"
		} else if name == "deno" {
			grammar.subcommands = "eval run"
		}
		return grammar
	case luaVersion.MatchString(name):
		grammar := interpreterOptionGrammar{code: "e", flags: "ivEW", values: "ljO"}
		if strings.HasPrefix(name, "luajit") {
			grammar.optional = "O"
		}
		return grammar
	case name == "php":
		return interpreterOptionGrammar{code: "rBRE", flags: "alHinqs", values: "cdftzF", longCode: "--run --process-begin --process-code --process-end", longValues: "--php-ini --define --file --docroot --zend-extension --process-file"}
	case name == "rscript":
		return interpreterOptionGrammar{code: "e", longValues: "--default-packages"}
	case name == "awk" || name == "gawk":
		return interpreterOptionGrammar{code: "e", values: "fFivW", longCode: "--source", longValues: "--file --field-separator --assign --include --load"}
	default:
		return interpreterOptionGrammar{}
	}
}

// Normalize attached executable option values before lexical launch analysis.
// Value-taking flags stop short-cluster parsing: their operand is not another
// option or source suffix. Positional filters and script-file roles stay intact.
func interpreterCodeArgs(name string, args []string) []string {
	normalized, _ := interpreterCodeArgsComplete(name, args)
	return normalized
}

// Required operands must be present, even when no attached source needed
// normalization. An explicitly empty operand still satisfies the option arity.
func interpreterCodeArgsComplete(name string, args []string) ([]string, bool) {
	grammar := interpreterOptions(name)
	var normalized []string
	skip, options := false, true
	for i, arg := range args {
		if skip {
			skip = false
			if normalized != nil {
				normalized = append(normalized, arg)
			}
			continue
		}
		if !options || arg == "--" {
			options = false
			if normalized != nil {
				normalized = append(normalized, arg)
			}
			continue
		}
		// A script operand ends option parsing. Do not turn option-looking
		// script arguments into executable source; raw witnesses still run.
		if (arg == "-" || !strings.HasPrefix(arg, "-")) && !optionIn(grammar.subcommands, arg) {
			options = false
		}
		option, source, attached, consumes, terminal := grammar.split(arg)
		skip = consumes
		// Python passes everything after its -c source or -m module to that
		// program. Those words cannot create pending interpreter operands.
		if terminal {
			options = false
		}
		if !attached {
			if normalized != nil {
				normalized = append(normalized, arg)
			}
			continue
		}
		if normalized == nil {
			normalized = append(make([]string, 0, len(args)+2), args[:i]...)
		}
		normalized = append(normalized, option, source)
		// Node's -pe cluster also has a code-bearing -p interpretation. Keep
		// both literal witnesses rather than hiding source starting with e.
		if javascriptInterpreter(name) && strings.HasSuffix(option, "p") && strings.HasPrefix(source, "e") && len(source) > 1 {
			normalized = append(normalized, option+"e", source[1:])
		}
	}
	if skip {
		return nil, false
	}
	if normalized == nil {
		return args, true
	}
	return normalized, true
}

// Source roles apply after attached options have been normalized. Other argv
// words remain data even when they contain source-language quote characters.
func interpreterSourceArgs(name string, args []string) []bool {
	grammar := interpreterOptions(name)
	sources := make([]bool, len(args))
	options, positionalSource := true, name == "awk" || name == "gawk"
	for i := 0; i < len(args) && options; i++ {
		arg := args[i]
		if arg == "--" {
			if positionalSource && i+1 < len(args) {
				sources[i+1] = true
			}
			break
		}
		if optionIn(grammar.subcommands, arg) {
			positionalSource = name == "deno" && arg == "eval"
			continue
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			sources[i] = positionalSource
			break
		}
		option, _, _, consumes, terminal := grammar.split(arg)
		if option != "" {
			positionalSource = false
		}
		if (name == "awk" || name == "gawk") && (arg == "-f" || strings.HasPrefix(arg, "-f") || arg == "--file" || strings.HasPrefix(arg, "--file=")) {
			positionalSource = false
		}
		if consumes {
			i++
			if i < len(args) {
				sources[i] = option != ""
			}
		}
		if terminal {
			options = false
		}
	}
	return sources
}

func (g interpreterOptionGrammar) split(arg string) (option, source string, attached, consumes, terminal bool) {
	if strings.HasPrefix(arg, "--") {
		key, value, equals := strings.Cut(arg, "=")
		if optionIn(g.longCode, key) {
			return key, value, equals, !equals, false
		}
		return "", "", false, !equals && optionIn(g.longValues, key), false
	}
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false, false, false
	}
	for i := 1; i < len(arg); i++ {
		ch := rune(arg[i])
		if strings.ContainsRune(g.code, ch) {
			return arg[:i+1], arg[i+1:], i+1 < len(arg), i+1 == len(arg), strings.ContainsRune(g.terminal, ch)
		}
		// Perl -0/-l and Ruby -0/-W consume optional numeric values, then may
		// continue a cluster. Arbitrary value-taking flags stop it instead.
		if strings.ContainsRune(g.numeric, ch) {
			for i+1 < len(arg) && arg[i+1] >= '0' && arg[i+1] <= '9' {
				i++
			}
			continue
		}
		if strings.ContainsRune(g.values, ch) {
			return "", "", false, i+1 == len(arg) && !strings.ContainsRune(g.optional, ch), strings.ContainsRune(g.terminal, ch)
		}
		if !strings.ContainsRune(g.flags, ch) {
			break
		}
	}
	return "", "", false, false, false
}
