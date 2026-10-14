package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// commandSlot handles argv positions that an application executes as commands.
// Unlike generic prose arguments, these must be certifiable shell text.
func (a *analyzer) commandSlot(name string, args []string, depth int, cwd string) bool {
	strict := func(code string) bool {
		a.shellValue(code, depth, cwd)
		return true
	}
	switch name {
	case "flock", "su", "runuser", "expect", "npm", "npx", "make", "rsync":
		for i, arg := range args {
			key, attached, hasValue := strings.Cut(arg, "=")
			slot := (name == "flock" || name == "su" || name == "runuser" || name == "expect") && (arg == "-c" || key == "--command") ||
				(name == "npm" && len(args) > 0 && args[0] == "exec" || name == "npx") && (arg == "-c" || key == "--call") ||
				name == "make" && (arg == "--eval" || key == "--eval") ||
				name == "rsync" && (arg == "-e" || key == "--rsh")
			if slot {
				if hasValue {
					return strict(attached)
				}
				if i+1 >= len(args) {
					a.reason = roles.Indeterminate
					return true
				}
				return strict(args[i+1])
			}
			if name == "make" && (arg == "-f" || arg == "--file" || key == "--file" || strings.HasPrefix(arg, "-f") && len(arg) > 2) {
				file := attached
				if strings.HasPrefix(arg, "-f") && len(arg) > 2 {
					file = arg[2:]
				}
				if !hasValue && arg == "-f" || arg == "--file" {
					if i+1 < len(args) {
						file = args[i+1]
					}
				}
				if strings.HasPrefix(file, "/dev/") || strings.HasPrefix(file, "<(") || strings.HasPrefix(file, ">(") {
					a.reason = roles.Indeterminate
					return true
				}
			}
		}
	case "watch", "tmux", "screen", "ssh":
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
		if len(args) >= 4 && args[0] == "alias" && args[1] == "set" {
			for _, arg := range args[3:] {
				if strings.HasPrefix(arg, "!") {
					return strict(strings.TrimPrefix(arg, "!"))
				}
			}
		}
	}
	return false
}
