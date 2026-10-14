package policy

import "strings"

// shellPathOption marks shell switches that can change path interpretation.
func shellPathOption(name string) bool {
	return name == "cdable_vars" || name == "autocd" || name == "extglob"
}

// shellPathOptions recognizes normalized options after the shell parser removes quotes.
func shellPathOptions(name string, args []string) bool {
	if name != "shopt" && name != "set" {
		return false
	}
	active := name == "shopt"
	for _, arg := range args {
		if arg == "-s" || arg == "-o" {
			active = true
			continue
		}
		if arg == "-u" || arg == "+o" {
			active = false
			continue
		}
		if active && shellPathOption(arg) {
			return true
		}
	}
	return false
}

// indirectConsumer identifies commands whose environment or shell path may be consulted.
func indirectConsumer(name string) bool {
	return name == "git" || name == "rg" || name == "bash" || name == "sh" || name == "zsh" || name == "ksh" || name == "ksh93" || name == "mksh" || name == "dash" || name == "ash" || name == "yash" || name == "posh" || name == "fish" || name == "csh" || name == "tcsh" || name == "env" || name == "command" || name == "builtin"
}

// sensitiveIndirect identifies variables interpreted by Git, shells or ripgrep.
func sensitiveIndirect(name string) bool {
	return strings.HasPrefix(name, "GIT_") || name == "EDITOR" || name == "VISUAL" || name == "PAGER" || name == "BASH_ENV" || name == "ENV" || name == "RIPGREP_CONFIG_PATH"
}

// recordIndirect retains a conservative flag until the end of the analyzed source.
func (a *analyzer) recordIndirect(name string, args []string, unknown bool) {
	mark := func(value string) {
		if value == "" || sensitiveIndirect(value) || strings.ContainsAny(value, "$`{}[]*") {
			a.indirect = true
		}
	}
	switch name {
	case "printf":
		for i, arg := range args {
			if arg == "-v" && i+1 < len(args) {
				mark(args[i+1])
			}
			if strings.HasPrefix(arg, "-v") && len(arg) > 2 {
				mark(arg[2:])
			}
		}
	case "declare", "typeset", "local":
		nameref := false
		for _, arg := range args {
			if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "+") {
				if strings.Contains(arg, "n") {
					nameref = true
				}
				continue
			}
			key, value, hasValue := strings.Cut(arg, "=")
			if nameref {
				mark(key)
				if hasValue {
					mark(value)
				}
			} else if unknown {
				mark("")
			}
		}
	case "read":
		for i := 0; i < len(args); i++ {
			if args[i] == "-a" && i+1 < len(args) {
				mark(args[i+1])
				i++
				continue
			}
			if strings.HasPrefix(args[i], "-") {
				if args[i] == "-d" || args[i] == "-p" || args[i] == "-n" || args[i] == "-N" || args[i] == "-t" || args[i] == "-u" {
					i++
				}
				continue
			}
			mark(args[i])
		}
	case "mapfile", "readarray":
		if len(args) == 0 {
			mark("MAPFILE")
		} else {
			mark(args[len(args)-1])
		}
	case "export":
		if unknown {
			mark("")
		}
		// Literal export names are direct assignments, not indirect writes.
	case "eval":
		a.indirect = true
	}
}
