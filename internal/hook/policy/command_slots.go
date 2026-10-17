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

// Launcher command slots share option normalization with the interactive-shell
// check, so attached values and long prefixes do not lose their command role.
func shellCommandOption(arg string) bool {
	key, _, _ := strings.Cut(arg, "=")
	return strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--") || key == "--command" || strings.HasPrefix(key, "--co") && strings.HasPrefix("--command", key)
}

// commandSlot handles argv positions that an application executes as commands.
// Unlike generic prose arguments, these must be certifiable shell text.
func (a *analyzer) commandSlot(name string, args []string, depth int, cwd string) bool {
	if name == "make" {
		args = roles.NormalizeMakeArgs(args)
	}
	strict := func(code string) bool { return a.strictCommandSlot(name, code, depth, cwd) }
	handled := false
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
		for i := 0; i < len(args); i++ {
			arg := args[i]
			if name == "make" {
				if arg == "--" {
					break
				}
				if optionIn("-C -I -o -W --directory --include-dir --old-file --assume-old --what-if --new-file --assume-new", arg) {
					i++
					if i >= len(args) {
						a.reason = roles.Indeterminate
						return true
					}
					continue
				}
				if strings.Contains(arg, "=") && !strings.HasPrefix(arg, "-") {
					_, value, _ := strings.Cut(arg, "=")
					if strings.Contains(value, "$(") || strings.Contains(value, "${") || strings.Contains(value, "`") {
						a.reason = roles.Indeterminate
						return true
					}
				}
			}
			key, attached, hasValue := strings.Cut(arg, "=")
			slot := (name == "flock" || name == "su" || name == "runuser" || name == "expect") && shellCommandOption(arg) ||
				(name == "npm" && npmExec || optionIn("npx pnpm yarn", name)) && packageCallOption(arg) ||
				name == "make" && (arg == "-E" || strings.HasPrefix(arg, "-E") && len(arg) > 2 || strings.HasPrefix("--eval", key) && len(key) >= 3 && strings.HasPrefix(key, "--e")) ||
				name == "rsync" && (arg == "-e" || key == "--rsh" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg[1:], "e"))
			if slot {
				value := attached
				if name == "rsync" && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
					value = strings.SplitN(arg[1:], "e", 2)[1]
					hasValue = value != ""
				} else if len(arg) > 2 && (strings.HasPrefix(arg, "-c") || strings.HasPrefix(arg, "-E")) && !strings.HasPrefix(arg, "--") {
					value, hasValue = arg[2:], true
				}
				if !hasValue {
					i++
					if i >= len(args) {
						a.reason = roles.Indeterminate
						return true
					}
					value = args[i]
				}
				handled = true
				strict(value)
				if a.reason != "" {
					return true
				}
				// A safe first value does not certify later executable options.
				// Consume each slot operand exactly once, including option-like data.
				continue
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
					i++
					file = args[i]
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
	return handled
}
