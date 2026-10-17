package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// Application directory options affect only that command and its children, not
// the next shell statement. Make applies repeated -C sequentially; Compose
// resolves the selected project directory against the original process cwd.
func (a *analyzer) commandCWD(name string, args []string, cwd string) string {
	if name != "make" && name != "docker" && name != "docker-compose" {
		return cwd
	}
	base := cwd
	compose := name == "docker-compose"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if name == "docker" && arg == "compose" {
			compose = true
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		directory := name == "make" && key == "--directory" || compose && key == "--project-directory"
		if name == "make" {
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
				for j := 1; j < len(arg); j++ {
					// Required values consume the remaining cluster or the
					// next word; optional values consume only the suffix.
					// In particular, a C inside -fFILE is not a directory.
					if strings.ContainsRune("CfIoWE", rune(arg[j])) {
						directory = arg[j] == 'C'
						value, attached = arg[j+1:], j+1 < len(arg)
						if !directory && !attached {
							i++
						}
						break
					}
					if strings.ContainsRune("jlO", rune(arg[j])) {
						break
					}
				}
			} else if !attached && optionIn("--file --makefile --include-dir --old-file --assume-old --what-if --new-file --assume-new --eval", key) {
				i++
			}
		}
		if !directory {
			continue
		}
		if !attached {
			i++
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return ""
			}
			value = args[i]
		}
		anchor := base
		if name == "make" {
			anchor = cwd
		}
		cwd = a.resolve(value, anchor)
	}
	return cwd
}
