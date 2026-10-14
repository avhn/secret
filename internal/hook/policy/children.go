package policy

import (
	"path"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// metadataChild is an allowlist, not a list of known readers. Wrappers do not
// change whether the underlying child consumes the supplied file contents.
func (a *analyzer) metadataChild(words []string, depth int, cwd string) bool {
	if depth > 4 || len(words) == 0 {
		return false
	}
	name, args := path.Base(words[0]), words[1:]
	if _, ok := utilityTable[name]; ok {
		child, dir, shell := a.utilityChild(name, args, cwd)
		return !shell && a.metadataChild(child, depth+1, dir)
	}
	if name == "command" || name == "builtin" {
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		return a.metadataChild(args, depth+1, cwd)
	}
	if name == "env" {
		for len(args) > 0 {
			if args[0] == "--" {
				args = args[1:]
				break
			}
			if args[0] == "-i" || args[0] == "--ignore-environment" {
				args = args[1:]
				continue
			}
			if strings.Contains(args[0], "=") && !strings.HasPrefix(args[0], "-") {
				args = args[1:]
				continue
			}
			if args[0] == "-u" || args[0] == "--unset" {
				if len(args) < 2 {
					return false
				}
				args = args[2:]
				continue
			}
			if strings.HasPrefix(args[0], "-") {
				return false
			}
			break
		}
		return a.metadataChild(args, depth+1, cwd)
	}
	return optionIn("ls stat chmod chown rm rmdir touch mkdir test true false basename dirname realpath readlink file", name)
}

func (a *analyzer) parallelCommand(args []string, depth int, cwd string) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		key, _, attached := strings.Cut(args[0], "=")
		args = args[1:]
		if optionIn("-j --jobs -a --arg-file -I --replace --delimiter", key) {
			if key == "-a" || key == "--arg-file" {
				a.reason = roles.Indeterminate
				return
			}
			if !attached {
				if len(args) == 0 {
					a.reason = roles.Indeterminate
					return
				}
				args = args[1:]
			}
		} else if !optionIn("-0 --null --no-run-if-empty --keep-order -k --verbose -v --will-cite --", key) || attached {
			a.reason = roles.Indeterminate
			return
		}
	}
	if len(args) == 0 {
		a.reason = roles.Indeterminate
		return
	}
	if !a.metadataChild(args, depth+1, cwd) && a.treeProtectedAll(".", cwd) {
		a.reason = roles.FileInput
		return
	}
	for _, arg := range args {
		if arg == ":::" || arg == "::::" {
			a.reason = roles.Indeterminate
			return
		}
	}
	a.command(args, depth+1, cwd, false)
}

// jq's -f is a flag. Its first positional is the program file, even when
// intervening flags or a short-option cluster follow -f.
func (a *analyzer) jqInputs(args []string, cwd string) {
	fromFile, options := false, true
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg, "=")
			switch key {
			case "--from-file":
				if attached {
					a.reason = roles.Indeterminate
					return
				}
				fromFile = true
			case "--arg", "--argjson", "--rawfile", "--slurpfile":
				if attached || i+2 >= len(args) {
					a.reason = roles.Indeterminate
					return
				}
				if (key == "--rawfile" || key == "--slurpfile") && a.inputProtected(args[i+2], cwd) {
					a.reason = roles.FileInput
					return
				}
				i += 2
			case "--indent", "-L":
				if !attached {
					i++
					if i >= len(args) {
						a.reason = roles.Indeterminate
						return
					}
					value = args[i]
				}
				_ = value
			default:
				if !optionIn("--null-input --raw-input --slurp --compact-output --raw-output --raw-output0 --join-output --ascii-output --sort-keys --color-output --monochrome-output --tab --unbuffered --stream --stream-errors --seq --exit-status --binary --args --jsonargs --version --help --build-configuration", key) || attached {
					a.reason = roles.Indeterminate
					return
				}
			}
		} else {
			for j := 1; j < len(arg); j++ {
				flag := arg[j]
				if flag == 'f' {
					fromFile = true
					continue
				}
				if flag == 'L' {
					if j+1 == len(arg) {
						i++
						if i >= len(args) {
							a.reason = roles.Indeterminate
							return
						}
					}
					break
				}
				if !strings.ContainsRune("nRscrjSaCMebhV", rune(flag)) {
					a.reason = roles.Indeterminate
					return
				}
			}
		}
	}
	if fromFile {
		if len(positional) == 0 {
			a.reason = roles.Indeterminate
			return
		}
		if a.inputProtected(positional[0], cwd) {
			a.reason = roles.FileInput
			return
		}
	}
}
