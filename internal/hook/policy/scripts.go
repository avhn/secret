package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

var awkFileCommand = regexp.MustCompile(`(?:getline|print|printf)[^;\n{}]*[<>][ \t]*["']([^"']+)["']`)
var awkShellCommand = regexp.MustCompile(`system[ \t]*\([ \t]*["']([^"']*)["'][ \t]*\)`)

// Script files are inspected only when small, regular and safely named.
// Inline literal roles use the same metadata path boundary as operands.
func (a *analyzer) scriptInputs(name string, args []string, depth int, cwd string) {
	if name == "sed" {
		args = a.sedScripts(args, cwd)
	}
	if a.reason != "" {
		return
	}
	if name == "sed" {
		// GNU sed separates successive -e/-f sources with a newline.
		args = []string{strings.Join(args, "\n")}
	}
	for _, arg := range args {
		if name != "sed" && (strings.HasPrefix(arg, "--file") || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "f")) {
			a.reason = roles.Indeterminate
			return
		}
		if name == "sed" {
			a.parseSedScript(arg, depth, cwd)
		} else {
			for _, match := range awkFileCommand.FindAllStringSubmatch(arg, -1) {
				if a.inputProtected(match[1], cwd) {
					a.reason = roles.FileInput
					return
				}
			}
			for _, match := range awkShellCommand.FindAllStringSubmatch(arg, -1) {
				a.shellValue(match[1], depth, cwd)
			}
		}
	}
}

// sedScripts shares sed's option arities, including -neSCRIPT clusters.
func (a *analyzer) sedScripts(args []string, cwd string) []string {
	var scripts, positional []string
	options := true
	consume := func(i *int, value string, attached bool) string {
		if attached {
			return value
		}
		(*i)++
		if *i >= len(args) {
			a.reason = roles.Indeterminate
			return ""
		}
		return args[*i]
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg[2:], "=")
			key = uniqueOption(key, "expression file quiet silent debug follow-symlinks in-place line-length posix regexp-extended separate sandbox unbuffered null-data help version")
			switch key {
			case "expression":
				scripts = append(scripts, consume(&i, value, attached))
			case "file":
				scripts = append(scripts, a.sedFile(consume(&i, value, attached), cwd))
			case "line-length":
				consume(&i, value, attached)
			case "in-place":
			case "quiet", "silent", "debug", "follow-symlinks", "posix", "regexp-extended", "separate", "sandbox", "unbuffered", "null-data", "help", "version":
				if attached {
					a.reason = roles.Indeterminate
					return nil
				}
			default:
				a.reason = roles.Indeterminate
				return nil
			}
		} else {
			for j := 1; j < len(arg); j++ {
				switch arg[j] {
				case 'e':
					scripts = append(scripts, consume(&i, arg[j+1:], j+1 < len(arg)))
					j = len(arg)
				case 'f':
					scripts = append(scripts, a.sedFile(consume(&i, arg[j+1:], j+1 < len(arg)), cwd))
					j = len(arg)
				case 'l':
					consume(&i, arg[j+1:], j+1 < len(arg))
					j = len(arg)
				case 'i':
					j = len(arg)
				case 'n', 'E', 'r', 'z', 's', 'u':
				default:
					a.reason = roles.Indeterminate
					return nil
				}
			}
		}
	}
	if len(scripts) == 0 && len(positional) > 0 {
		scripts = append(scripts, positional[0])
	}
	return scripts
}

// sedFile reads only bounded regular script files; symlinks, stdin sources,
// missing files and oversized scripts deny because their content is uncertain.
func (a *analyzer) sedFile(name, cwd string) string {
	// Standard-input script sources cannot be read from the command line.
	if name == "-" || name == "/dev/stdin" || name == "/proc/self/fd/0" {
		a.reason = roles.Indeterminate
		return ""
	}
	if name == "" || a.inputProtected(name, cwd) {
		a.reason = roles.FileInput
		return ""
	}
	file := filepath.FromSlash(a.resolve(name, cwd))
	// A symlink can lead to /dev/stdin in the child even when the hook's
	// own stdin resolves to an innocuous regular file.
	info, statErr := os.Lstat(file)
	if statErr != nil || !info.Mode().IsRegular() {
		a.reason = roles.Indeterminate
		return ""
	}
	target, err := filepath.EvalSymlinks(file)
	if err != nil {
		a.reason = roles.Indeterminate
		return ""
	}
	data, err := boundedMetadata(target, 8192)
	if err != nil || bytes.IndexByte(data, 0) >= 0 || !isRegularScript(file) {
		a.reason = roles.Indeterminate
		return ""
	}
	return string(data)
}

func isRegularScript(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}
