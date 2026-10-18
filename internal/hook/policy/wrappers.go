package policy

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// utilityOptions mirrors the retained guard's option arities. A short option
// with a value consumes the rest of its cluster or the next argv entry.
type utilityOptions struct{ values, flags, longValues, longFlags, optional string }

var utilityTable = map[string]utilityOptions{
	"time":        {"fo", "pavq", "format output", "portability append verbose quiet help version", ""},
	"ionice":      {"cnpPu", "t", "class classdata pid pgid uid", "ignore help version", ""},
	"chrt":        {"PTD", "afmorRbiIpv", "sched-runtime sched-period sched-deadline", "all-tasks fifo max other pid rr reset-on-fork batch idle verbose help version", ""},
	"taskset":     {"", "acp", "", "all-tasks cpu-list pid help version", ""},
	"doas":        {"uC", "Lns", "", "", ""},
	"watch":       {"n", "bcdetpxw", "interval", "beep color errexit precise exec no-title no-wrap help version", "differences"},
	"flock":       {"wE", "suxnFo", "timeout conflict-exit-code", "shared exclusive unlock nonblock no-fork close verbose help version", ""},
	"unbuffer":    {"", "p", "", "", ""},
	"timeout":     {"sk", "v", "signal kill-after", "foreground preserve-status verbose help version", ""},
	"gtimeout":    {"sk", "v", "signal kill-after", "foreground preserve-status verbose help version", ""},
	"nice":        {"n", "", "adjustment", "help version", ""},
	"exec":        {"a", "cl", "", "", ""},
	"stdbuf":      {"ioe", "", "input output error", "help version", ""},
	"caffeinate":  {"tw", "dimsu", "", "", ""},
	"nohup":       {"", "", "", "help version", ""},
	"systemd-run": {"uHM", "PGqtd", "unit host machine description slice service-type working-directory uid gid nice setenv expand-environment", "user system scope pipe wait collect quiet pty send-sighup no-block remain-after-exit same-dir help version", ""},
	"xargs":       {"nLIsPEJdRSa", "0rtpxo", "max-args max-chars max-procs delimiter arg-file", "null no-run-if-empty verbose interactive exit open-tty help version", "max-lines replace eof"},
	"sudo":        {"ughpCDRTU", "AbEHKklnPSVvsi", "user group host prompt close-from chdir chroot command-timeout other-user", "askpass background preserve-env set-home reset-timestamp remove-timestamp list non-interactive preserve-groups stdin version validate help shell login", ""},
}

// optionIn matches complete option names, never substrings of another option.
func optionIn(list, name string) bool {
	return strings.Contains(" "+list+" ", " "+name+" ") && name != ""
}

// filenamePipelineRecipient replaces inherited file-input provenance when a pipe
// supplies stdin. The recipient's own redirects are applied by singleStmt.
func (a *analyzer) filenamePipelineRecipient(cmd *syntax.BinaryCmd, depth int, cwd string) string {
	prior := a.filenameStdin
	if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
		a.filenameStdin = false
	}
	defer func() { a.filenameStdin = prior }()
	return a.pipelineRecipient(cmd, depth, cwd)
}

// utilityChild returns the real child after consuming known options. It also
// checks xargs input lists and propagates scoped directory/environment operands
// and sudo's shell mode.
func (a *analyzer) utilityChild(name string, args []string, cwd string) ([]string, string, bool) {
	table := utilityTable[name]
	if name == "systemd-run" {
		// Retain the existing opaque-launcher literal protection while adding
		// precise child selection and cwd handling.
		for _, arg := range args {
			if hasProtectedLiteral(arg) {
				a.reason = roles.FileInput
				return nil, cwd, false
			}
		}
	}
	base := cwd
	var assignments []string
	shell, watchExec, tasksetList, tasksetPID := false, false, false, false
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
				if name == "sudo" && key == "chdir" || name == "systemd-run" && key == "working-directory" {
					cwd = a.resolve(value, base)
				}
				// A bare --setenv name inherits user configuration (P8), not a
				// command-text value. Register only explicit assignments.
				if name == "systemd-run" && key == "setenv" && strings.Contains(value, "=") {
					if _, _, appendValue, known := declarationOperand(value); !known || appendValue {
						a.reason = roles.Indeterminate
						return nil, cwd, shell
					}
					assignments = append(assignments, value)
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
			if name == "taskset" {
				tasksetList = tasksetList || key == "cpu-list"
				tasksetPID = tasksetPID || key == "pid"
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
			if name == "taskset" {
				tasksetList = tasksetList || flag == 'c'
				tasksetPID = tasksetPID || flag == 'p'
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
		if name == "taskset" {
			// A PID query has no child. Launch mode requires both a valid
			// hexadecimal mask/CPU list and a remaining executable.
			if tasksetPID && len(args) == 1 && tasksetDecimal.MatchString(args[0]) {
				return nil, cwd, shell
			}
			valid := tasksetMask.MatchString(args[0])
			if tasksetList {
				valid = tasksetCPUs.MatchString(args[0])
			}
			if len(args) < 2 || !valid {
				a.reason = roles.Indeterminate
				return nil, cwd, shell
			}
		}
		args = args[1:] // scheduling priority, CPU mask/list, or lock file/fd
	}
	if name == "timeout" || name == "gtimeout" {
		if len(args) < 2 {
			a.reason = roles.Indeterminate
			return nil, cwd, shell
		}
		args = args[1:] // the duration belongs to timeout, not its child
	}
	// systemd-run's environment options become child-local assignment operands,
	// consumed by the dispatcher just like sudo's environment operands.
	if len(assignments) > 0 {
		args = append(assignments, args...)
	}
	return args, cwd, shell
}

var (
	tasksetDecimal = regexp.MustCompile(`^[0-9]+$`)
	tasksetMask    = regexp.MustCompile(`^(0[xX])?[0-9a-fA-F]+$`)
	tasksetCPUs    = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(:[0-9]+)?(,[0-9]+(-[0-9]+)?(:[0-9]+)?)*$`)
)

// setsid has only these inert options. Unknown flags must not hide a child.
func (a *analyzer) setsidChild(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if !optionIn("-w --wait -c --ctty -f --fork", arg) {
			a.reason = roles.Indeterminate
			return nil
		}
	}
	return args
}

// env appends trailing argv after splitting its option value. Those operands
// are literal data, never another opportunity for shell expansion.
func envSplitCommand(value string, tail []string) string {
	var code strings.Builder
	code.WriteString("env ")
	code.WriteString(splitEnv(value))
	for _, arg := range tail {
		code.WriteString(" '")
		code.WriteString(strings.ReplaceAll(arg, "'", "'\\''"))
		code.WriteByte('\'')
	}
	return code.String()
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

// stdinRedirect retains file-supplied filename uncertainty through wrappers and
// compound commands. Redirects of other descriptors do not supply xargs stdin.
func stdinRedirect(redirect *syntax.Redirect) bool {
	if redirect.N != nil && strings.TrimLeft(redirect.N.Value, "0") != "" {
		return false
	}
	return optionIn("< <> <& << <<- <<<", redirect.Op.String())
}

// An explicit argument file supplies operands instead of cwd/stdin.
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
