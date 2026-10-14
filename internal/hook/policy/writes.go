package policy

import (
	"os"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
)

// writeProtected applies the same configuration target rule as file tools and patches.
func (a *analyzer) writeProtected(name, cwd string) bool {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if inline, ok := a.env["XDG_CONFIG_HOME"]; ok {
		xdg = inline
	}
	global := os.Getenv("GIT_CONFIG_GLOBAL")
	if inline, ok := a.env["GIT_CONFIG_GLOBAL"]; ok {
		global = inline
	}
	return paths.ConfigWriteProtected(name, cwd, "", a.home, xdg, global)
}

// writeCommand checks known output roles before generic reader classification.
func (a *analyzer) writeCommand(name string, args []string, cwd string) bool {
	target := func(value string) bool {
		if a.writeProtected(value, cwd) {
			a.reason = "git configuration write target"
			return true
		}
		return false
	}
	switch name {
	case "tee", "touch", "truncate", "vim", "vi", "nvim", "nano", "micro", "hx", "kak", "code", "codium", "subl", "mate", "emacs", "emacsclient", "ex":
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") && target(arg) {
				return true
			}
		}
	case "cp", "mv", "ln", "install", "rsync":
		for i, arg := range args {
			if arg == "-t" || arg == "--target-directory" {
				if i+1 < len(args) && target(args[i+1]) {
					return true
				}
			}
			if strings.HasPrefix(arg, "--target-directory=") && target(strings.TrimPrefix(arg, "--target-directory=")) {
				return true
			}
		}
		if len(args) > 1 && target(args[len(args)-1]) {
			return true
		}
	case "dd":
		for _, arg := range args {
			if strings.HasPrefix(arg, "of=") && target(strings.TrimPrefix(arg, "of=")) {
				return true
			}
		}
	case "sed", "perl":
		inplace := false
		for _, arg := range args {
			if arg == "-i" || strings.HasPrefix(arg, "-i") || arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") {
				inplace = true
			}
		}
		if inplace {
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") && target(arg) {
					return true
				}
			}
		}
	}
	return false
}
