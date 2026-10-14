package policy

import (
	"path"
	"regexp"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

var shellVersion = regexp.MustCompile(`^(?:bash|rbash|sh|zsh|ksh|mksh|dash|ash|yash|posh|fish|csh|tcsh|hush|msh)(?:[-.]?[0-9][0-9.-]*)?$`)

func shellName(name string) bool { return shellVersion.MatchString(strings.ToLower(path.Base(name))) }

// shellScriptIndex returns the position of a script source, or -1 for stdin.
func shellScriptIndex(name string, args []string) int {
	_, index, _, _ := shellArguments(name, args)
	return index
}

// shellArguments consumes options even when -c precedes other flags. The first
// non-option word after them is the code string, not another switch.
func shellArguments(name string, args []string) (bool, int, []string, bool) {
	command := false
	var init []string
	end := false
	for i := 0; i < len(args); i++ {
		word := args[i]
		if !end && word == "--" {
			end = true
			continue
		}
		if !end && (word == "--rcfile" || word == "--init-file" || word == "--init-command" || word == "-C" && name == "fish" || word == "-d" && name == "fish" || word == "-o" || word == "+o" || word == "-O" || word == "+O") {
			if i+1 >= len(args) {
				return command, -1, init, true
			}
			if word == "--init-command" || word == "-C" && name == "fish" {
				init = append(init, args[i+1])
			}
			if word == "--rcfile" || word == "--init-file" {
				init = append(init, "\x00"+args[i+1])
			}
			if (word == "-o" || word == "-O") && shellPathOption(args[i+1]) {
				init = append(init, "\x01")
			}
			i++
			continue
		}
		if !end && strings.HasPrefix(word, "--init-command=") && name == "fish" {
			init = append(init, strings.TrimPrefix(word, "--init-command="))
			continue
		}
		if !end && (strings.HasPrefix(word, "--rcfile=") || strings.HasPrefix(word, "--init-file=")) {
			_, value, _ := strings.Cut(word, "=")
			init = append(init, "\x00"+value)
			continue
		}
		if !end && (strings.HasPrefix(word, "-d") && name == "fish" && len(word) > 2) {
			continue
		}
		if !end && (strings.HasPrefix(word, "-C") && name == "fish" && len(word) > 2) {
			init = append(init, word[2:])
			continue
		}
		if !end && len(word) > 1 && (word[0] == '-' || word[0] == '+') && word[1] != '-' {
			for j := 1; j < len(word); j++ {
				switch word[j] {
				case 'c':
					if word[0] == '-' {
						command = true
					}
				case 'o', 'O':
					value := word[j+1:]
					// In -oc and -Oc, c remains a command flag and
					// the option name is the following argument.
					if value == "c" && word[0] == '-' {
						command = true
						value = ""
					}
					if value == "" {
						i++
						if i >= len(args) {
							return command, -1, init, true
						}
						value = args[i]
					}
					if shellPathOption(value) {
						init = append(init, "\x01")
					}
					j = len(word)
				}
			}
			continue
		}
		if !end && strings.HasPrefix(word, "-") && word != "-" {
			continue
		}
		if word == "-" && !command {
			continue
		}
		return command, i, init, false
	}
	return command, -1, init, false
}

func (a *analyzer) shellCommand(name string, args []string, depth int, cwd string) {
	code, index, init, bad := shellArguments(name, args)
	if name == "fish" && index >= 0 && code {
		for i := index + 1; i < len(args); i++ {
			v := args[i]
			if v == "-C" || v == "--init-command" {
				i++
				if i >= len(args) {
					bad = true
					break
				}
				init = append(init, args[i])
			} else if strings.HasPrefix(v, "--init-command=") {
				init = append(init, strings.TrimPrefix(v, "--init-command="))
			}
		}
	}
	if bad {
		a.reason = roles.Indeterminate
		return
	}
	for _, value := range init {
		if value == "\x01" {
			cwd = ""
			continue
		}
		if strings.HasPrefix(value, "\x00") {
			if !a.certifiableShellFile(value[1:], cwd) {
				a.reason = roles.Indeterminate
				return
			}
		} else {
			a.shellValue(value, depth, cwd)
			if a.reason != "" {
				return
			}
		}
	}
	if index < 0 {
		a.reason = roles.Indeterminate
		return
	}
	if a.cdpath {
		cwd = ""
	}
	if code {
		a.shellValue(args[index], depth, cwd)
	} else if !a.certifiableShellFile(args[index], cwd) {
		a.reason = roles.Indeterminate
	}
}

// modelledCommand keeps opaque strings out of Git messages and other commands
// whose operand grammar is already explicitly classified.
func modelledCommand(name string) bool {
	if optionIn("git sed awk gawk jq yq tar bsdtar unzip cpio 7z 7za find rg docker dotenv secret xargs parallel sudo env command builtin exec timeout gtimeout nice time setsid script busybox toybox sh", name) {
		return true
	}
	if _, ok := utilityTable[name]; ok {
		return true
	}
	if roles.KnownReader(name) || roles.PrinterReason(name, nil, false) != "" {
		return true
	}
	if optionIn("npm go make echo printf ls stat file wc cp mv ln install rsync dd tee touch truncate mkdir patch shopt set cd pushd popd dirs true false test for", name) {
		return true
	}
	return false
}

func knownNested(name string) bool {
	name = strings.ToLower(path.Base(name))
	return shellName(name) || modelledCommand(name) || optionIn("cat head tail grep rg git sed perl python python3 ruby node echo printf tee patch tar mkdir cp mv ssh docker npm go", name)
}

// Unknown launchers can pass commands in any argv suffix or opaque code word.
func (a *analyzer) unknownExecution(args []string, depth int, cwd string) {
	for i, value := range args {
		if strings.ContainsAny(value, " \t\n;|&$`><()") {
			a.shellValue(value, depth, cwd)
			if a.reason != "" {
				return
			}
		}
		if knownNested(value) {
			a.command(args[i:], depth+1, cwd, false)
			if a.reason != "" {
				return
			}
		}
	}
}
