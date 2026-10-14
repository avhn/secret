package roles

import "strings"

const recursiveGrep = "recursive grep bypasses protected search defaults; use plain rg"

// longOption resolves exact names and unique GNU-style abbreviations. Unknown
// or ambiguous options cannot certify the roles of the following operands.
func longOption(arg string, names string) (string, string, bool, bool) {
	key, value, attached := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
	match := ""
	for _, name := range strings.Fields(names) {
		if key == name {
			return name, value, attached, true
		}
		if key != "" && strings.HasPrefix(name, key) {
			if match != "" {
				return "", "", false, false
			}
			match = name
		}
	}
	return match, value, attached, match != ""
}

// GrepReason parses options before assigning pattern and file roles. Short
// options that take arguments consume the rest of a cluster, even r or R.
func GrepReason(args []string, protected func(string) bool) string {
	const longs = "extended-regexp fixed-strings basic-regexp perl-regexp regexp file ignore-case no-ignore-case word-regexp line-regexp null-data no-messages invert-match version help max-count byte-offset line-number line-buffered with-filename no-filename label only-matching quiet silent binary-files text directories devices recursive dereference-recursive include exclude exclude-from exclude-dir files-without-match files-with-matches count initial-tab null before-context after-context context group-separator no-group-separator color colour binary unix-byte-offsets"
	options, explicitPattern := true, false
	var operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		var opts []string
		value, attached := "", false
		if strings.HasPrefix(arg, "--") {
			name, v, has, ok := longOption(arg, longs)
			if !ok {
				return Indeterminate
			}
			opts, value, attached = []string{name}, v, has
		} else {
			for j := 1; j < len(arg); j++ {
				c := arg[j]
				if !strings.ContainsRune("EFGPe:fiwxzsvVmbnHhoqaIdDrRLlcTZBACUu0123456789", rune(c)) {
					return Indeterminate
				}
				opts = append(opts, string(c))
				if strings.ContainsRune("efmABCDd", rune(c)) {
					value, attached = arg[j+1:], j+1 < len(arg)
					break
				}
			}
		}
		for _, opt := range opts {
			switch opt {
			case "r", "R", "recursive", "dereference-recursive":
				return recursiveGrep
			case "e", "regexp", "f", "file", "exclude-from", "m", "max-count", "A", "after-context", "B", "before-context", "C", "context", "d", "directories", "D", "devices", "label", "binary-files", "include", "exclude", "exclude-dir", "group-separator":
				if !attached {
					i++
					if i >= len(args) {
						return Indeterminate
					}
					value = args[i]
				}
				if opt == "d" || opt == "directories" {
					if value == "recurse" {
						return recursiveGrep
					}
				}
				if opt == "f" || opt == "file" || opt == "exclude-from" {
					if protected(value) {
						return FileInput
					}
				}
				if opt == "e" || opt == "regexp" || opt == "f" || opt == "file" {
					explicitPattern = true
				}
			}
		}
	}
	if !explicitPattern && len(operands) > 0 {
		operands = operands[1:]
	}
	for _, operand := range operands {
		if protected(operand) {
			return Reader
		}
	}
	return ""
}

// splitReason consumes all supported option arguments before selecting the
// first positional input. The optional second positional is an output prefix.
func splitReason(args []string, protected func(string) bool) string {
	const longs = "bytes line-bytes lines number additional-suffix filter elide-empty-files numeric-suffixes hex-suffixes suffix-length verbose separator help version"
	options, input := true, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if strings.HasPrefix(arg, "--") {
				name, _, attached, ok := longOption(arg, longs)
				if !ok || name == "filter" {
					return Indeterminate
				}
				switch name {
				case "bytes", "line-bytes", "lines", "number", "additional-suffix", "suffix-length", "separator":
					if !attached {
						i++
						if i >= len(args) {
							return Indeterminate
						}
					}
				}
			} else {
				for j := 1; j < len(arg); j++ {
					if strings.ContainsRune("bClnat", rune(arg[j])) {
						if j+1 == len(arg) {
							i++
							if i >= len(args) {
								return Indeterminate
							}
						}
						break
					}
					if !strings.ContainsRune("edx0123456789", rune(arg[j])) {
						return Indeterminate
					}
				}
			}
			continue
		}
		if !input {
			if protected(arg) {
				return FileInput
			}
			input = true
		}
	}
	return ""
}

// sedReason handles scripts attached within short-option clusters, so -nep
// consumes p as the script and leaves the next argument in its file-input role.
func sedReason(args []string, protected func(string) bool) string {
	options, script := true, false
	var files []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			files = append(files, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, attached, ok := longOption(arg, "expression file quiet silent debug follow-symlinks in-place line-length posix regexp-extended separate sandbox unbuffered null-data help version")
			if !ok {
				return Indeterminate
			}
			if name == "expression" || name == "file" || name == "line-length" {
				if !attached {
					i++
					if i >= len(args) {
						return Indeterminate
					}
					value = args[i]
				}
				if name == "file" && protected(value) {
					return FileInput
				}
				if name != "line-length" {
					script = true
				}
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			flag := arg[j]
			if flag == 'i' {
				break
			} // optional suffix is attached only
			if flag == 'e' || flag == 'f' || flag == 'l' {
				value := arg[j+1:]
				if value == "" {
					i++
					if i >= len(args) {
						return Indeterminate
					}
					value = args[i]
				}
				if flag == 'f' && protected(value) {
					return FileInput
				}
				if flag != 'l' {
					script = true
				}
				break
			}
			if !strings.ContainsRune("nErzsu", rune(flag)) {
				return Indeterminate
			}
		}
	}
	if !script && len(files) > 0 {
		files = files[1:]
	}
	for _, file := range files {
		if protected(file) {
			return Reader
		}
	}
	return ""
}
