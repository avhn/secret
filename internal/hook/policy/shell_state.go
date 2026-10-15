package policy

import (
	"os"
	"path"
	"path/filepath"
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
		name := strings.ToLower(path.Base(words[0]))
		if _, ok := utilityTable[name]; !ok || name == "xargs" {
			break
		}
		child, _, shell := a.utilityChild(name, words[1:], cwd)
		if a.reason != "" || shell && len(child) == 0 {
			return true // A wrapper-created shell without code reads stdin.
		}
		if shell {
			return false // The sudo child is analyzed as shell text by dispatch.
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
	name := strings.ToLower(path.Base(words[0]))
	args := words[1:]
	if name == "env" || name == "command" || name == "builtin" || name == "exec" {
		for len(args) > 0 {
			arg := args[0]
			if name == "env" && (arg == "-S" || arg == "--split-string" || strings.HasPrefix(arg, "-S") && len(arg) > 2 || strings.HasPrefix(arg, "--split-string=")) {
				return false // The split-string child is classified by command dispatch.
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
		name = strings.ToLower(path.Base(args[0]))
		args = args[1:]
	}
	if name == "setsid" {
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			args = args[1:]
		}
		return shellStdinWords(args)
	}
	if name == "script" {
		for i, arg := range args {
			if arg == "-c" || arg == "-qc" || arg == "-cq" {
				if i+1 < len(args) {
					return shellStdinWords(strings.Fields(args[i+1]))
				}
				return true
			}
		}
		return false
	}
	if name == "busybox" || name == "toybox" {
		if len(args) == 0 {
			return false
		}
		name = strings.ToLower(path.Base(args[0]))
		args = args[1:]
	}
	if !shellName(name) {
		return false
	}
	return shellScriptIndex(name, args) == -1

}

// certifiableShellFile excludes descriptor aliases, unreadable files and
// symlinked or non-regular shell startup scripts.
func (a *analyzer) certifiableShellFile(name, cwd string) bool {
	if name == "" || a.inputProtected(name, cwd) {
		return false
	}
	file := filepath.FromSlash(name)
	if !filepath.IsAbs(file) {
		file = filepath.Join(cwd, file)
	}
	info, err := os.Lstat(file)
	return err == nil && info.Mode().IsRegular()
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

// launcherStdin rejects uncategorized scripts supplied through stdin.
func launcherStdin(call *syntax.CallExpr, redirs []*syntax.Redirect) bool {
	if len(call.Args) == 0 {
		return false
	}
	name := strings.ToLower(path.Base(literal(call.Args[0])))
	if !optionIn("doas run0 pkexec expect runuser su machinectl sudo script systemd-run", name) {
		return false
	}
	for _, r := range redirs {
		if strings.HasPrefix(r.Op.String(), "<") {
			return true
		}
	}
	return false
}

func launcherShellOption(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "si") {
			return true
		}
	}
	return false
}

func launcherStdinStatement(stmt *syntax.Stmt) bool {
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
		return optionIn("doas run0 pkexec su runuser machinectl sudo script expect systemd-run", strings.ToLower(path.Base(literal(call.Args[0]))))
	}
	return false
}
