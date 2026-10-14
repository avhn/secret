package policy

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// inputProtected keeps unknown shell directories and process-relative aliases
// out of the filesystem existence exception for bare operands.
func (a *analyzer) inputProtected(name, cwd string) bool {
	p := path.Clean(name)
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if strings.HasPrefix(p, "/dev/fd/") || p == "/dev/fd" || len(parts) >= 3 && parts[0] == "proc" && (parts[2] == "cwd" || parts[2] == "root") {
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

// hookAssignment checks only variables interpreted by a shell, never ordinary
// assignment data. No assignment value is evaluated to determine its contents.
func (a *analyzer) hookAssignment(key, value string, depth int, cwd string) {
	switch key {
	case "BASH_ENV", "ENV":
		if value == "" || a.inputProtected(value, cwd) {
			a.reason = roles.FileInput
		}
	case "PS4", "PROMPT_COMMAND", "SHELLOPTS", "BASHOPTS":
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
	if name == "jq" || name == "diff" {
		for i, arg := range args {
			value := ""
			if name == "diff" && (strings.HasPrefix(arg, "--from-file=") || strings.HasPrefix(arg, "--to-file=")) || name == "jq" && strings.HasPrefix(arg, "--from-file=") {
				_, value, _ = strings.Cut(arg, "=")
			}
			if name == "jq" && (arg == "--from-file" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "f")) {
				if j := strings.IndexByte(arg, 'f'); !strings.HasPrefix(arg, "--") && j+1 < len(arg) {
					value = arg[j+1:]
				} else if i+1 < len(args) {
					value = args[i+1]
				} else {
					a.reason = roles.Indeterminate
					return true
				}
			}
			if value != "" && a.inputProtected(value, cwd) {
				a.reason = roles.FileInput
				return true
			}
		}
	}
	if name == "git" {
		a.gitHistory(args, depth, cwd)
	}
	if name == "tar" || name == "unzip" {
		a.archiveInputs(name, args, cwd)
	}
	return a.reason != ""
}

// repoRoot uses metadata only. Object history and git configuration are never
// read or executed. A missing root cannot certify a historical content dump.
func repoRoot(cwd string) string {
	if !filepath.IsAbs(cwd) {
		return ""
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
}

func (a *analyzer) gitHistory(args []string, depth int, cwd string) {
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		v := args[i]
		i++
		if v == "-C" || v == "--work-tree" || v == "--git-dir" {
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return
			}
			cwd = a.resolve(args[i], cwd)
			i++
			continue
		}
		config := ""
		if v == "-c" {
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return
			}
			config = args[i]
			i++
		} else if strings.HasPrefix(v, "-c") {
			config = v[2:]
		}
		key, value, _ := strings.Cut(config, "=")
		key = strings.ToLower(key)
		if strings.HasPrefix(key, "alias.") && strings.HasPrefix(value, "!") {
			a.fragmentAt(value[1:], depth+1, cwd)
		}
		if key == "core.pager" || key == "core.sshcommand" || key == "core.fsmonitor" || key == "sequence.editor" {
			a.fragmentAt(value, depth+1, cwd)
		}
	}
	if i >= len(args) {
		return
	}
	sub := args[i]
	args = args[i+1:]
	root := repoRoot(cwd)
	history := sub == "show" || sub == "archive"
	explicit, safe := false, true
	revisions := 0
	for j, v := range args {
		if v == "--" {
			explicit = j+1 < len(args)
			for _, spec := range args[j+1:] {
				if paths.LexicalProtected(spec, cwd, a.home) {
					a.reason = roles.FileInput
					return
				}
				if strings.ContainsAny(spec, ":*?[") || a.treeProtected(spec, cwd) {
					safe = false
				}
			}
			break
		}
		if _, member, ok := strings.Cut(v, ":"); ok && !strings.HasPrefix(v, "-") && paths.LexicalProtected(member, root, a.home) {
			a.reason = roles.FileInput
			return
		}
		if !strings.HasPrefix(v, "-") {
			revisions++
		}
		if sub == "log" && (v == "--patch" || v == "-u" || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.Contains(v, "p")) {
			history = true
		}
		if sub == "format-patch" && v == "--stdout" || sub == "cat-file" && (v == "-p" || strings.HasPrefix(v, "--batch")) {
			history = true
		}
		if sub == "diff" && strings.Contains(v, "..") {
			history = true
		}
	}
	if sub == "diff" && revisions >= 2 || sub == "grep" && revisions >= 2 {
		history = true
	}
	if history && !(explicit && safe) && (root == "" || a.treeProtected(root, root)) {
		a.reason = roles.FileInput
	}
}

// archiveInputs separates archive filenames and option values from creation
// inputs and extraction member names. Members are lexical names, not cwd files.
func (a *analyzer) archiveInputs(name string, args []string, cwd string) {
	create, members, options := false, false, true
	type archiveInput struct{ name, cwd string }
	inputs := []archiveInput{}
	consume := func(i *int, attached string) string {
		if attached != "" {
			return attached
		}
		(*i)++
		if *i >= len(args) {
			a.reason = roles.Indeterminate
			return ""
		}
		return args[*i]
	}
	for i := 0; i < len(args); i++ {
		v := args[i]
		if options && v == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(v, "--") {
			key, value, attached := strings.Cut(v, "=")
			switch key {
			case "--create":
				create = true
			case "--extract", "--get", "--list":
				members = true
			case "--file", "--directory", "--exclude", "--transform", "--strip-components", "--blocking-factor", "--format", "--label", "--suffix", "--files-from", "--exclude-from":
				if !attached {
					value = consume(&i, "")
				}
				if key == "--directory" {
					cwd = a.resolve(value, cwd)
				}
				if key == "--files-from" {
					a.reason = roles.Indeterminate
					return
				}
				if key == "--exclude-from" && a.inputProtected(value, cwd) {
					a.reason = roles.FileInput
					return
				}
			}
			continue
		}
		oldStyle := name == "tar" && i == 0 && !strings.HasPrefix(v, "-") && strings.Trim(v, "cxtfruvhOpzjJaAbBkKmMoPsSwWZ0123456789") == ""
		if options && (strings.HasPrefix(v, "-") && v != "-" || oldStyle) {
			flags := strings.TrimPrefix(v, "-")
			for j := 0; j < len(flags); j++ {
				flag := flags[j]
				if name == "unzip" {
					members = members || flag == 'p' || flag == 'c'
					continue
				}
				switch flag {
				case 'c':
					create = true
				case 'x', 't':
					members = true
				case 'f', 'C', 'T', 'X':
					value := ""
					if !oldStyle {
						value = flags[j+1:]
					}
					value = consume(&i, value)
					if flag == 'C' {
						cwd = a.resolve(value, cwd)
					}
					if flag == 'T' {
						a.reason = roles.Indeterminate
						return
					}
					if flag == 'X' && a.inputProtected(value, cwd) {
						a.reason = roles.FileInput
						return
					}
					if !oldStyle {
						j = len(flags)
					}
				}
			}
			continue
		}
		inputs = append(inputs, archiveInput{v, cwd})
	}
	if name == "unzip" && len(inputs) > 0 {
		inputs = inputs[1:]
	}
	for _, v := range inputs {
		if create && a.treeProtectedAll(v.name, v.cwd) || members && paths.LexicalProtected(v.name, v.cwd, a.home) {
			a.reason = roles.FileInput
			return
		}
	}
}

func (a *analyzer) dotenvChild(args []string, depth int, cwd string) {
	for i := 0; i < len(args); i++ {
		v := args[i]
		switch v {
		case "--":
			a.command(args[i+1:], depth+1, cwd, false)
			return
		case "-p", "--print":
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
