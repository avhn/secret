package policy

import "strings"

type interpreterOptionGrammar struct {
	code, flags, numeric, values string
	longCode, longValues         string
	subcommands                  string
}

func interpreterOptions(name string) interpreterOptionGrammar {
	switch {
	case pythonInterpreter(name):
		return interpreterOptionGrammar{code: "c", flags: "bBdEhiIOPqRsSuvVx", values: "mWX", longValues: "--check-hash-based-pycs"}
	case name == "ruby":
		return interpreterOptionGrammar{code: "e", flags: "acdhlnpsSvwy", numeric: "0W", values: "CEFIKr", longValues: "--encoding --external-encoding --internal-encoding --backtrace-limit"}
	case name == "perl":
		return interpreterOptionGrammar{code: "eE", flags: "acdfhnpsStTuUvwWxX", numeric: "0l", values: "CFIiMm"}
	case javascriptInterpreter(name):
		grammar := interpreterOptionGrammar{code: "ep", flags: "ci", values: "r", longCode: "--eval --print", longValues: "--env-file --env-file-if-exists --require --import --loader --experimental-loader --input-type --inspect-port --title"}
		if name == "bun" {
			grammar.subcommands = "run"
		} else if name == "deno" {
			grammar.subcommands = "eval run"
		}
		return grammar
	case luaVersion.MatchString(name):
		return interpreterOptionGrammar{code: "e", flags: "ivEW", values: "ljO"}
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
		option, source, attached, consumes := grammar.split(arg)
		skip = consumes
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
	if normalized == nil {
		return args
	}
	return normalized
}

func (g interpreterOptionGrammar) split(arg string) (option, source string, attached, consumes bool) {
	if strings.HasPrefix(arg, "--") {
		key, value, equals := strings.Cut(arg, "=")
		if optionIn(g.longCode, key) {
			return key, value, equals, !equals
		}
		return "", "", false, !equals && optionIn(g.longValues, key)
	}
	if len(arg) < 2 || arg[0] != '-' {
		return "", "", false, false
	}
	for i := 1; i < len(arg); i++ {
		ch := rune(arg[i])
		if strings.ContainsRune(g.code, ch) {
			return arg[:i+1], arg[i+1:], i+1 < len(arg), i+1 == len(arg)
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
			return "", "", false, i+1 == len(arg)
		}
		if !strings.ContainsRune(g.flags, ch) {
			break
		}
	}
	return "", "", false, false
}
