package policy

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

var shellVersion = regexp.MustCompile(`^(?:bash|rbash|sh|zsh|ksh|mksh|dash|ash|yash|posh|fish|csh|tcsh|hush|msh)(?:[0-9._-][a-z0-9._-]*)?$`)

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
		if !end && word == "-" && i == len(args)-1 && !command {
			return false, -1, init, false
		}
		if !end && (word == "--" || word == "-") {
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

		return command, i, init, false
	}
	return command, -1, init, false
}

func (a *analyzer) shellCommand(name string, args []string, depth int, cwd string) {
	// A child shell's IFS assignments cannot change the caller's word splitting
	// or reuse its source-position proof for later sibling commands.
	modified, empty, source := a.ifsModified, a.ifsEmpty, a.ifsSource
	value, assigned := a.env["IFS"]
	count, counted := a.assignments["IFS"]
	defer func() {
		a.ifsModified, a.ifsEmpty, a.ifsSource = modified, empty, source
		if assigned {
			a.env["IFS"] = value
		} else {
			delete(a.env, "IFS")
		}
		if counted {
			a.assignments["IFS"] = count
		} else {
			delete(a.assignments, "IFS")
		}
	}()
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
	if optionIn("setsid curl git gh kubectl secret sed awk gawk jq yq find xargs parallel sudo su env command builtin exec timeout gtimeout nice time nohup sh npx npm pnpm yarn pipx uvx dotenv dotenv-cli dotenvx", name) {
		return true
	}
	if _, ok := utilityTable[name]; ok {
		return true
	}

	if optionIn("echo printf ls stat file wc cp mv ln install dd tee touch truncate mkdir patch shopt set cd pushd popd dirs true false test for fd fdfind", name) {
		return true
	}
	return false
}

// unmodelledCommand has no operand grammar; only these argv data operands
// receive the P18 raw-token check, including the host's direct argv route.
func unmodelledCommand(name string) bool {
	// systemd-run keeps its opaque-argument protection in addition to precise
	// child and working-directory parsing.
	return name == "systemd-run" || !modelledCommand(name) && !shellName(name) && !roles.KnownReader(name) &&
		!optionIn("tar bsdtar unzip cpio 7z 7za split dotenv eval docker openssl zip rsync scp du realpath readlink basename dirname chmod chown chgrp rm find [ [[", name)
}

func knownNested(name string) bool {
	name = strings.ToLower(path.Base(name))
	return shellName(name) || interpreter(name) || modelledCommand(name) || roles.KnownReader(name) || optionIn("cat head tail grep rg git sed perl python python3 ruby node echo printf tee patch tar mkdir cp mv ssh docker npm go", name)
}

// genericShellText is best-effort: prose or invalid shell syntax in an
// ordinary argument cannot become an accidental fail-closed command slot.
func (a *analyzer) genericShellText(value string, depth int, cwd string) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(value), "")
	if len(file.Stmts) == 0 {
		return
	}
	if err != nil {
		// A malformed prose suffix cannot erase completed command witnesses.
		// Only the parsed prefix has shell roles; do not certify the suffix.
		value = value[:file.Stmts[len(file.Stmts)-1].End().Offset()]
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok {
			for _, redir := range stmt.Redirs {
				if strings.HasPrefix(redir.Op.String(), "<") && redir.Word != nil && paths.LexicalProtected(literal(redir.Word), cwd, a.home) {
					a.reason = roles.FileInput
				}
			}
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 1 && optionIn("source .", literal(call.Args[0])) && paths.LexicalProtected(literal(call.Args[1]), cwd, a.home) {
			a.reason = roles.FileInput
		}
		return a.reason == ""
	})
	if a.reason != "" {
		return
	}
	probe := *a
	// A partial parse supplies positive role witnesses, not unknown-launcher
	// operand slots in language source or prose such as "const env = {}".
	probe.literalFallback = err != nil
	probe.credentialConfigs = slices.Clone(a.credentialConfigs)
	probe.reason, probe.uncertain, probe.structuralUncertain = "", false, false
	probe.env = make(map[string]string)
	for key, val := range a.env {
		probe.env[key] = val
	}
	probe.fragmentAt(value, depth+1, cwd)
	if probe.reason != "" && probe.reason != roles.Indeterminate {
		a.reason = probe.reason
	} else if probe.reason == roles.Indeterminate && knownNested(commandName(file.Stmts[0])) {
		a.reason = probe.reason
	}
}

// Unknown launchers can pass commands in any argv suffix or opaque code word.
func (a *analyzer) unknownExecution(args []string, depth int, cwd string) {
	for i, value := range args {
		if strings.HasPrefix(value, "--") {
			if _, suffix, ok := strings.Cut(value, "="); ok && strings.ContainsAny(suffix, " \t\n;|&$`><(){}") {
				a.genericShellText(suffix, depth, cwd)
			}
		}
		if strings.ContainsAny(value, " \t\n;|&$`><(){}") {
			a.genericShellText(value, depth, cwd)
		}
		if a.reason != "" {
			return
		}
		if optionIn("env printenv", strings.ToLower(path.Base(value))) {
			a.reason = roles.Printer
			return
		}
		if knownNested(value) || roles.PrinterReason(strings.ToLower(path.Base(value)), args[i+1:], false) != "" {
			a.command(args[i:], depth+1, cwd, false)
			if a.reason != "" {
				return
			}
		}
	}
}
