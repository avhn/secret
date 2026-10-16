package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

func (a *analyzer) strictCommandSlot(name, code string, depth int, cwd string) bool {
	if hasProtectedLiteral(code) || a.inlineGitDir(code, cwd) {
		a.reason = roles.FileInput
		return true
	}
	if name == "make" {
		if !strings.ContainsAny(code, ":=\n") {
			a.reason = roles.Indeterminate
			return true
		}
		for _, line := range strings.Split(code, "\n") {
			recipe := line
			if _, after, ok := strings.Cut(line, ";"); ok {
				recipe = after
			}
			recipe = strings.TrimLeft(strings.TrimSpace(recipe), "@+- \t")
			if recipe != "" && !strings.HasSuffix(recipe, ":") {
				a.shellValue(recipe, depth, cwd)
				if a.reason != "" {
					return true
				}
			}
		}
	}
	a.shellValue(code, depth, cwd)
	return true
}

// commandSlot handles argv positions that an application executes as commands.
// Unlike generic prose arguments, these must be certifiable shell text.
func (a *analyzer) commandSlot(name string, args []string, depth int, cwd string) bool {
	strict := func(code string) bool { return a.strictCommandSlot(name, code, depth, cwd) }
	if name == "yarn" || name == "pnpm" {
		leading := args
		for len(leading) > 0 && strings.HasPrefix(leading[0], "-") {
			key, value, attached := strings.Cut(leading[0], "=")
			leading = leading[1:]
			if optionIn("-C --dir --cwd --filter", key) {
				if !attached {
					if len(leading) == 0 {
						a.reason = roles.Indeterminate
						return true
					}
					value, leading = leading[0], leading[1:]
				}
				if key != "--filter" {
					cwd = a.resolve(value, cwd)
				}
			} else if strings.HasPrefix(key, "-C") && len(key) > 2 {
				cwd = a.resolve(key[2:], cwd)
			}
		}
		if len(leading) == 0 || leading[0] != "exec" {
			return false
		}
		args = leading[1:]
		if name == "yarn" {
			for len(args) > 0 && optionIn("-s --silent --", args[0]) {
				option := args[0]
				args = args[1:]
				if option == "--" {
					break
				}
			}
			if len(args) == 0 || !strings.HasPrefix(args[0], "-") {
				return strict(strings.Join(args, " "))
			}
		}
	}
	switch name {
	case "flock", "su", "runuser", "expect", "npm", "npx", "pnpm", "yarn", "make", "rsync":
		npmExec := false
		if name == "npm" {
			for _, arg := range args {
				if arg == "exec" || arg == "x" {
					npmExec = true
					break
				}
			}
		}
		for i, arg := range args {
			if name == "make" {
				if strings.Contains(arg, "=") && !strings.HasPrefix(arg, "-") {
					_, value, _ := strings.Cut(arg, "=")
					if strings.Contains(value, "$(") || strings.Contains(value, "${") || strings.Contains(value, "`") {
						a.reason = roles.Indeterminate
						return true
					}
				}
			}
			key, attached, hasValue := strings.Cut(arg, "=")
			slot := (name == "flock" || name == "su" || name == "runuser" || name == "expect") && (arg == "-c" || strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--") || key == "--command" || strings.HasPrefix(key, "--co") && strings.HasPrefix("--command", key)) ||
				(name == "npm" && npmExec || optionIn("npx pnpm yarn", name)) && packageCallOption(arg) ||
				name == "make" && (arg == "-E" || strings.HasPrefix(arg, "-E") && len(arg) > 2 || strings.HasPrefix("--eval", key) && len(key) >= 3 && strings.HasPrefix(key, "--e")) ||
				name == "rsync" && (arg == "-e" || key == "--rsh" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "e"))
			if slot {
				if name == "rsync" && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "e") && arg != "-e" {
					suffix := strings.SplitN(arg[1:], "e", 2)[1]
					if suffix != "" {
						return strict(suffix)
					}
				}
				if arg == "-E" {
					if i+1 >= len(args) {
						a.reason = roles.Indeterminate
						return true
					}
					return strict(args[i+1])
				}
				if len(arg) > 2 && (strings.HasPrefix(arg, "-c") || strings.HasPrefix(arg, "-E")) && !strings.HasPrefix(arg, "--") {
					return strict(arg[2:])
				}
				if hasValue {
					return strict(attached)
				}
				if i+1 >= len(args) {
					a.reason = roles.Indeterminate
					return true
				}
				return strict(args[i+1])
			}
			if name == "make" && (strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "f") || arg == "--file" || arg == "--makefile" || key == "--file" || key == "--makefile" || strings.HasPrefix(arg, "-f") && len(arg) > 2) {
				file := attached
				if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "f") {
					file = strings.SplitN(arg[1:], "f", 2)[1]
				}
				if file == "" && (strings.Contains(arg, "f") || arg == "--file" || arg == "--makefile") {
					if i+1 >= len(args) {
						a.reason = roles.Indeterminate
						return true
					}
					file = args[i+1]
				}
				if file == "-" || strings.HasPrefix(file, "/dev/") || strings.HasPrefix(file, "<(") || strings.HasPrefix(file, ">(") {
					a.reason = roles.Indeterminate
					return true
				}
				if a.inputProtected(file, cwd) {
					a.reason = roles.FileInput
					return true
				}
				resolved := a.resolve(file, cwd)
				info, err := os.Stat(filepath.Clean(resolved))
				if err == nil && !info.Mode().IsRegular() {
					a.reason = roles.Indeterminate
					return true
				}
				if err != nil && !os.IsNotExist(err) {
					a.reason = roles.Indeterminate
					return true
				}
			}
		}
	case "tmux", "screen", "ssh":
		start := 0
		if name == "ssh" {
			start = 1
		}
		for start < len(args) && strings.HasPrefix(args[start], "-") {
			start++
		}
		if start < len(args) {
			if name == "ssh" {
				start++
			}
			if start >= len(args) {
				return false
			}
			if shellName(args[start]) || knownNested(args[start]) {
				a.command(args[start:], depth+1, cwd, false)
				return a.reason != ""
			}
			return strict(strings.Join(args[start:], " "))
		}
	case "op":
		if len(args) > 2 && args[0] == "run" {
			for i, arg := range args {
				if arg == "--" && i+1 < len(args) {
					a.command(args[i+1:], depth+1, cwd, false)
					return a.reason != ""
				}
			}
		}
	case "gh":
		if len(args) >= 3 && args[0] == "alias" && args[1] == "set" {
			for _, arg := range args[2:] {
				if arg == "--shell" || strings.HasPrefix(arg, "--shell=") {
					a.reason = roles.Indeterminate
					return true
				}
				if strings.HasPrefix(arg, "!") {
					return strict(strings.TrimPrefix(arg, "!"))
				}
			}
		}
	}
	return false
}
