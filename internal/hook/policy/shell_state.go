package policy

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellPathOption marks shell switches that can change path interpretation.
func shellPathOption(name string) bool {
	return name == "cdable_vars" || name == "autocd" || name == "extglob" || name == "globstar"
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

// shellStdinStatement reports whether a pipeline supplies the shell's script.
func (a *analyzer) shellStdinStatement(stmt *syntax.Stmt, cwd string) bool {
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		words := make([]string, 0, len(cmd.Args))
		for _, word := range cmd.Args {
			words = append(words, literal(word))
		}
		return a.shellStdinWords(words, cwd)
	case *syntax.Subshell:
		for _, child := range cmd.Stmts {
			if a.shellStdinStatement(child, cwd) {
				return true
			}
		}
	case *syntax.Block:
		for _, child := range cmd.Stmts {
			if a.shellStdinStatement(child, cwd) {
				return true
			}
		}
	}
	return false
}

// shellStdinCall recognizes wrapped shells with no script file or inline -c source.
func (a *analyzer) shellStdinCall(call *syntax.CallExpr, cwd string) bool {
	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		words = append(words, literal(word))
	}
	return a.shellStdinWords(words, cwd)
}

// shellStdinWords follows literal command wrappers before checking shell options.
func (a *analyzer) shellStdinWords(words []string, cwd string) bool {
	for len(words) > 0 {
		name := path.Base(words[0])
		if _, ok := utilityTable[name]; !ok || name == "xargs" {
			break
		}
		child, _, shell := a.utilityChild(name, words[1:], cwd)
		if shell || a.reason != "" {
			return true // A wrapper-created shell cannot certify its stdin.
		}
		words = child
	}
	return shellStdinWords(words)
}

// shellStdinWords checks shell options after peeling env and multicall wrappers.
func shellStdinWords(words []string) bool {
	if len(words) == 0 {
		return false
	}
	name := path.Base(words[0])
	args := words[1:]
	if name == "env" || name == "command" || name == "builtin" || name == "exec" {
		for len(args) > 0 {
			arg := args[0]
			if name == "env" && (arg == "-S" || arg == "--split-string" || strings.HasPrefix(arg, "-S") && len(arg) > 2 || strings.HasPrefix(arg, "--split-string=")) {
				return true // Split-string may launch a shell that inherits stdin.
			}
			if name == "env" && strings.Contains(arg, "=") && !strings.HasPrefix(arg, "-") || arg == "--" || arg == "-i" || name == "command" && arg == "-p" {
				args = args[1:]
				continue
			}
			if name == "env" && (arg == "-u" || arg == "--unset" || arg == "-C" || arg == "--chdir") {
				if len(args) < 2 {
					return false
				}
				args = args[2:]
				continue
			}
			break
		}
		if len(args) == 0 {
			return false
		}
		name = path.Base(args[0])
		args = args[1:]
	}
	if name == "busybox" || name == "toybox" {
		if len(args) == 0 {
			return false
		}
		name = path.Base(args[0])
		args = args[1:]
	}
	if !optionIn("bash sh zsh ksh ksh93 mksh dash ash yash posh fish csh tcsh", name) {
		return false
	}
	stdin := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-s" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "s") {
			stdin = true
		}
		if arg == "-c" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "c") {
			return false
		}
		if arg == "-O" || arg == "+O" || arg == "-o" {
			i++
			continue
		}
		if arg == "-s" || arg == "--" || arg == "-" {
			continue
		}
		if strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "+") {
			continue
		}
		return stdin // After -s, remaining words are positional parameters.
	}
	return true
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
