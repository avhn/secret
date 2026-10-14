package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// utilityOptions mirrors the retained guard's option arities. A short option
// with a value consumes the rest of its cluster or the next argv entry.
type utilityOptions struct{ values, flags, longValues, longFlags, optional string }

var utilityTable = map[string]utilityOptions{
	"time":       {"", "p", "", "", ""},
	"timeout":    {"sk", "v", "signal kill-after", "foreground preserve-status verbose help version", ""},
	"gtimeout":   {"sk", "v", "signal kill-after", "foreground preserve-status verbose help version", ""},
	"nice":       {"n", "", "adjustment", "help version", ""},
	"exec":       {"a", "cl", "", "", ""},
	"stdbuf":     {"ioe", "", "input output error", "help version", ""},
	"caffeinate": {"tw", "dimsu", "", "", ""},
	"nohup":      {"", "", "", "help version", ""},
	"xargs":      {"nLIsPEJdRSa", "0rtpxo", "max-args max-chars max-procs delimiter arg-file", "null no-run-if-empty verbose interactive exit open-tty help version", "max-lines replace eof"},
	"sudo":       {"ughpCDRTU", "AbEHKklnPSVvsi", "user group host prompt close-from chdir chroot command-timeout other-user", "askpass background preserve-env set-home reset-timestamp remove-timestamp list non-interactive preserve-groups stdin version validate help shell login", ""},
}

// optionIn matches complete option names, never substrings of another option.
func optionIn(list, name string) bool {
	return strings.Contains(" "+list+" ", " "+name+" ") && name != ""
}

// utilityChild returns the real child after consuming known options. It also
// checks xargs input lists and propagates sudo's scoped directory and shell mode.
func (a *analyzer) utilityChild(name string, args []string, cwd string) ([]string, string, bool) {
	table := utilityTable[name]
	shell := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if name == "nice" && len(arg) > 1 && strings.Trim(arg[1:], "0123456789") == "" {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg[2:], "=")
			if optionIn(table.longValues, key) {
				if !attached {
					if len(args) == 0 {
						if name == "sudo" {
							return nil, cwd, shell
						}
						a.reason = roles.Indeterminate
						return nil, cwd, shell
					}
					value, args = args[0], args[1:]
				}
				if name == "xargs" && key == "arg-file" && a.protected(value, cwd) {
					a.reason = "xargs arg-file reads a protected store"
				}
				if name == "sudo" && key == "chdir" {
					cwd = a.resolve(value, cwd)
				}
			} else if optionIn(table.optional, key) {
				// GNU optional long arguments attach with = only.
			} else if !optionIn(table.longFlags, key) || attached {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
			if name == "sudo" && (key == "shell" || key == "login") {
				shell = true
			}
			continue
		}
		for i := 1; i < len(arg); i++ {
			flag := arg[i]
			if strings.ContainsRune(table.values, rune(flag)) {
				value := arg[i+1:]
				if value == "" {
					if len(args) == 0 {
						if name == "sudo" {
							return nil, cwd, shell
						}
						a.reason = roles.Indeterminate
						return nil, cwd, shell
					}
					value, args = args[0], args[1:]
				}
				if name == "xargs" && flag == 'a' && a.protected(value, cwd) {
					a.reason = "xargs arg-file reads a protected store"
				}
				if name == "sudo" && flag == 'D' {
					cwd = a.resolve(value, cwd)
				}
				break
			}
			if !strings.ContainsRune(table.flags, rune(flag)) {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
			if name == "sudo" && (flag == 's' || flag == 'i') {
				shell = true
			}
		}
	}
	if name == "timeout" || name == "gtimeout" {
		if len(args) == 0 {
			a.reason = roles.Indeterminate
			return nil, cwd, shell
		}
		args = args[1:] // the duration belongs to timeout, not its child
	}
	return args, cwd, shell
}
