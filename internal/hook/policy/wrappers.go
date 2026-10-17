package policy

import (
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// utilityOptions mirrors the retained guard's option arities. A short option
// with a value consumes the rest of its cluster or the next argv entry.
type utilityOptions struct{ values, flags, longValues, longFlags, optional string }

var utilityTable = map[string]utilityOptions{
	"time":       {"fo", "pavq", "format output", "portability append verbose quiet help version", ""},
	"ionice":     {"cnpPu", "t", "class classdata pid pgid uid", "ignore help version", ""},
	"chrt":       {"PTD", "afmorRbiIpv", "sched-runtime sched-period sched-deadline", "all-tasks fifo max other pid rr reset-on-fork batch idle verbose help version", ""},
	"taskset":    {"", "acp", "", "all-tasks cpu-list pid help version", ""},
	"doas":       {"uC", "Lns", "", "", ""},
	"watch":      {"n", "bcdetpxw", "interval", "beep color errexit precise exec no-title no-wrap help version", "differences"},
	"flock":      {"wE", "suxnFo", "timeout conflict-exit-code", "shared exclusive unlock nonblock no-fork close verbose help version", ""},
	"unbuffer":   {"", "p", "", "", ""},
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
	base := cwd
	shell, watchExec := false, false
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
						a.reason = roles.Indeterminate
						return nil, cwd, shell
					}
					value, args = args[0], args[1:]
				}
				if name == "xargs" && key == "arg-file" && a.protected(value, cwd) {
					a.reason = "xargs arg-file reads a protected store"
				}
				if name == "sudo" && key == "chdir" {
					cwd = a.resolve(value, base)
				}
			} else if optionIn(table.optional, key) {
				// GNU optional long arguments attach with = only.
			} else if !optionIn(table.longFlags, key) || attached {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
			if name == "watch" && key == "exec" {
				watchExec = true
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
						a.reason = roles.Indeterminate
						return nil, cwd, shell
					}
					value, args = args[0], args[1:]
				}
				if name == "xargs" && flag == 'a' && a.protected(value, cwd) {
					a.reason = "xargs arg-file reads a protected store"
				}
				if name == "sudo" && flag == 'D' {
					cwd = a.resolve(value, base)
				}
				break
			}
			if !strings.ContainsRune(table.flags, rune(flag)) {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
			if name == "watch" && flag == 'x' {
				watchExec = true
			}
			if name == "sudo" && (flag == 's' || flag == 'i') {
				shell = true
			}
		}
	}
	if name == "watch" {
		// watch normally joins argv into a shell command; --exec/-x opts out.
		if watchExec {
			return args, cwd, false
		}
		shell = true
		// The literal child is still classified by the ordinary dispatcher.
		if len(args) > 0 {
			return args, cwd, shell
		}
	}
	if name == "chrt" || name == "taskset" || name == "flock" {
		if len(args) == 0 {
			a.reason = roles.Indeterminate
			return nil, cwd, shell
		}
		if name == "chrt" {
			if _, err := strconv.Atoi(args[0]); err != nil {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
		}
		args = args[1:] // scheduling priority, CPU mask/list, or lock file/fd
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

// Child environment operands are already expanded argv, not shell source.
// Stop at the executable so its own NAME=VALUE data operands remain data.
func (a *analyzer) childAssignments(args []string, depth int, cwd string) ([]string, string) {
	for len(args) > 0 {
		key, value, appendValue, ok := declarationOperand(args[0])
		if !ok {
			break
		}
		if appendValue {
			a.hookAppend(key, value, depth, cwd)
		} else {
			a.hookAssignment(key, value, depth, cwd)
		}
		if key == "CDPATH" {
			a.cdpath = true
			cwd = ""
		}
		args = args[1:]
	}
	return args, cwd
}

// An explicit safe argument file supplies operands instead of cwd/stdin.
// Inspect only xargs options before the child, not a child's own -a flag.
func xargsHasArgFile(args []string) bool {
	table := utilityTable["xargs"]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}
		if strings.HasPrefix(arg, "--") {
			key, _, attached := strings.Cut(arg[2:], "=")
			if key == "arg-file" {
				return true
			}
			if optionIn(table.longValues, key) && !attached {
				i++
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			if arg[j] == 'a' {
				return true
			}
			if strings.ContainsRune(table.values, rune(arg[j])) {
				if j+1 == len(arg) {
					i++
				}
				break
			}
		}
	}
	return false
}
