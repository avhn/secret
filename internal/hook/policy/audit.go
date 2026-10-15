package policy

import (
	"path"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// inputProtected keeps unknown shell directories and process-relative aliases
// out of the filesystem existence exception for bare operands.
func (a *analyzer) inputProtected(name, cwd string) bool {
	p := path.Clean(name)
	if paths.ProcessAlias(p) {
		return true
	}
	if cwd == "" && !path.IsAbs(name) {
		return true
	}
	return a.protected(name, cwd)
}

func (a *analyzer) treeProtected(root, cwd string) bool {
	if time.Now().After(a.deadline) || cwd == "" && !path.IsAbs(root) {
		return true
	}
	return paths.TreeProtected(root, cwd, a.home)
}

// Append requires a known prior value for environment-sensitive names.
func (a *analyzer) hookAppend(key, value string, depth int, cwd string) {
	previous, known := a.env[key]
	if !known && (sensitiveIndirect(key) || gitShellEnv(key) || strings.HasPrefix(key, "LESS") || key == "POSIXLY_CORRECT") {
		a.reason = roles.Indeterminate
		return
	}
	a.hookAssignment(key, previous+value, depth, cwd)
}

// hookAssignment checks only variables interpreted by a shell, never ordinary
// assignment data. No assignment value is evaluated to determine its contents.
func (a *analyzer) hookAssignment(key, value string, depth int, cwd string) {
	if a.env == nil {
		a.env = make(map[string]string)
	}
	if previous, ok := a.env[key]; ok && previous != value {
		a.env[key] = "" // Branches and scoped assignments cannot certify a replacement.
	} else {
		a.env[key] = value
	}
	if key == "POSIXLY_CORRECT" {
		a.env[key] = value
	}
	if key == "GIT_EXEC_PATH" {
		a.reason = roles.Indeterminate
		return
	}
	if gitShellEnv(key) {
		a.editorPagerValue(key, value, cwd)
	}
	if strings.HasPrefix(key, "LESS") && key != "LESS" || key == "LESS" && !inertLessOption("-"+value) {
		a.reason = roles.Indeterminate
		return
	}
	switch key {
	case "BASH_ENV", "ENV":
		if value == "" || a.inputProtected(value, cwd) {
			a.reason = roles.FileInput
		} else if key == "BASH_ENV" {
			// A child shell sources this file; its code and path options are unknown.
			a.reason = roles.Indeterminate
		}
	case "SHELLOPTS", "BASHOPTS":
		if value == "" {
			a.reason = roles.Indeterminate
			return
		}
		for _, option := range strings.Split(value, ":") {
			if shellPathOption(option) {
				a.cdpath = true
			}
		}
	case "PS4", "PROMPT_COMMAND":
		if value == "" {
			a.reason = roles.Indeterminate
			return
		}
		a.fragmentAt(value, depth+1, cwd)
	}
}

// GNU env split-string has escapes which are not shell quoting. Decode these
// separators before parsing its child, rather than losing the backslash.
func splitEnv(s string) string {
	return strings.NewReplacer(`\_`, " ", `\t`, "\t", `\n`, "\n", `\r`, "\r").Replace(s)
}

func interpreter(name string) bool {
	return strings.HasPrefix(name, "python") || strings.Contains(" perl ruby node nodejs php awk gawk jq yq ", " "+name+" ")
}

func environmentCode(code string) bool {
	lower := strings.ToLower(code)
	return strings.Contains(lower, "environ") || strings.Contains(code, "ENV") || strings.Contains(lower, "getenv") || strings.Contains(lower, "strenv") || strings.Contains(lower, "process") && strings.Contains(lower, "env") || strings.Contains(code, "-MEnv")
}

// auditCommand checks roles whose inputs are not ordinary positional files.
// It returns true only when it supplied a denial; normal dispatch still runs.
func (a *analyzer) auditCommand(name string, args []string, depth int, cwd string, direct bool) bool {
	if name == "sed" || name == "awk" || name == "gawk" {
		a.scriptInputs(name, args, depth, cwd)
	}
	if a.reason != "" {
		return true
	}
	if strings.HasPrefix(name, "python") && len(args) >= 3 && args[0] == "-m" && args[1] == "dotenv" && args[2] == "list" {
		a.reason = roles.Printer
		return true
	}
	if interpreter(name) || name == "sed" || name == "vim" || name == "vi" || name == "nvim" || name == "ex" {
		skip := 0
		for i, code := range args {
			if skip > 0 {
				skip--
				continue
			}
			if (name == "jq" || name == "yq") && (code == "--arg" || code == "--argjson" || code == "--rawfile" || code == "--slurpfile") {
				skip = 2
				continue
			}
			if (name == "node" || name == "nodejs") && (code == "--env-file" || strings.HasPrefix(code, "--env-file=") || i > 0 && args[i-1] == "--env-file") {
				continue
			}
			if interpreter(name) && name != "jq" && environmentCode(code) && !direct {
				a.reason = roles.Printer
				return true
			}
			// Path-like script literals resolve through symlinks, matching the Bash guard.
			for _, token := range strings.FieldsFunc(code, func(r rune) bool { return strings.ContainsRune(" \t\n\"'`(){}[];<>=,+", r) }) {
				if name != "jq" && name != "yq" && (paths.LexicalProtected(token, cwd, a.home) || strings.Contains(token, "/") && paths.Protected(token, cwd, "", a.home)) {
					a.reason = roles.FileInput
					return true
				}
			}
			if name == "sed" {
				for j, r := range code {
					if r == 'e' && (j == 0 || code[j-1] >= '0' && code[j-1] <= '9') && j+1 < len(code) && code[j+1] == ' ' {
						a.fragmentAt(code[j+1:], depth+1, cwd)
					}
				}
			}
		}
	}
	if name == "jq" {
		a.jqInputs(args, cwd)
	}
	if name == "diff" {
		for _, arg := range args {
			if strings.HasPrefix(arg, "--from-file=") || strings.HasPrefix(arg, "--to-file=") {
				_, value, _ := strings.Cut(arg, "=")
				if a.inputProtected(value, cwd) {
					a.reason = roles.FileInput
				}
			}
		}
	}
	return a.reason != ""
}

func (a *analyzer) dotenvChild(args []string, depth int, cwd string) {
	for i := 0; i < len(args); i++ {
		v := args[i]
		switch v {
		case "--":
			a.command(args[i+1:], depth+1, cwd, false)
			return
		case "-p", "--print", "list":
			a.reason = roles.Printer
			return
		case "-e", "--env", "-v", "--variable":
			i++
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return
			}
		case "-c", "--cascade":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				if args[i] == "env" || args[i] == "printenv" {
					a.reason = roles.Printer
					return
				}
			}
		case "--debug", "-o", "--override", "--no-expand":
		default:
			if strings.HasPrefix(v, "--print=") {
				a.reason = roles.Printer
				return
			}
			if strings.HasPrefix(v, "--env=") || strings.HasPrefix(v, "--variable=") || strings.HasPrefix(v, "--cascade=") {
				continue
			}
			if strings.HasPrefix(v, "-") {
				a.reason = roles.Indeterminate
				return
			}
			a.command(args[i:], depth+1, cwd, false)
			return
		}
	}
}

// A branch, zero-iteration loop or uncalled function can leave either cwd.
// Retain uncertainty rather than selecting the last syntactic directory.
func joinedCWD(before, after string) string {
	if before != after {
		return ""
	}
	return before
}

func (a *analyzer) treeProtectedAll(root, cwd string) bool {
	if time.Now().After(a.deadline) || cwd == "" && !path.IsAbs(root) {
		return true
	}
	return paths.TreeProtectedScope(root, cwd, a.home, true)
}

func invalidControls(source string) bool {
	return strings.IndexFunc(source, func(r rune) bool { return r < 32 && r != '\n' && r != '\t' || r == 127 }) >= 0
}
