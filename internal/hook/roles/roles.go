// Package roles classifies shell commands by their file and output roles.
// Callers must supply already bounded, non-executed shell words.
package roles

import (
	"regexp"
	"strings"
)

const (
	FileInput     = "file input targets a protected store"
	Reader        = "reader targets a protected store"
	Printer       = "credential printer requires a direct pipe to secret stash FILE KEY or a password-stdin login"
	Indeterminate = "command too complex to analyse for secret access; split it or use secret run"
)

var jqEnvironment = regexp.MustCompile(`(^|[^A-Za-z0-9_."'])(env|\$ENV)([^A-Za-z0-9_]|$)`)

var readers = map[string]bool{}
var metadata = map[string]bool{}
var credential = regexp.MustCompile(`(?i)\$\{?[a-z0-9_]*(token|secret|pass(word|wd)?|api_?key|private_key|credential|_key)[a-z0-9_]*\}?`)

func init() {
	for _, name := range strings.Fields("cat bat less more head tail grep egrep fgrep rg ag ack ack-grep sed awk gawk perl python python3 ruby node source . xxd od hexdump strings cut sort uniq base64 jq yq tr nl tac rev diff cmp vim vi nvim nano emacs pbcopy open wc") {
		readers[name] = true
	}
	for _, name := range strings.Fields("ls stat test [ [[ realpath readlink basename dirname chmod chown chgrp touch rm") {
		metadata[name] = true
	}
}

// CredentialExpansion recognises an active credential-variable reference.
func CredentialExpansion(text string) bool { return credential.MatchString(text) }

// KnownReader checks a named reader without guessing an unknown command's role.
func KnownReader(name string) bool { return readers[name] }

// Reading reports whether a command consumes positional file inputs.
func Reading(name string) bool {
	return readers[name] || !metadata[name] && name != "echo" && name != "printf"
}

// PrinterReason identifies output which cannot enter agent context. A direct
// stdout pipe is permitted only for a validated stash or password-stdin login.
func PrinterReason(name string, args []string, direct bool) string {
	options := normalizePrinter(name, args)
	commands := options.words
	contains := func(words ...string) bool { return orderedWords(commands, words...) }
	arg := func(n int) string {
		if n < len(args) {
			return args[n]
		}
		return ""
	}
	printValue, always := false, false
	switch name {
	case "env", "printenv", "pbpaste", "wl-paste", "envsubst":
		printValue = true
	case "xclip", "xsel":
		printValue = options.flags["-o"] || options.flags["--output"] || options.flags["-out"] || options.flags["-output"]
	case "keyring":
		printValue = printerAction(commands, "get set del diagnose") == "get" && !options.flags["--help"] && !options.flags["-h"]
	case "gh", "glab":
		always = name == "gh" && contains("config", "get", "oauth_token")
		printValue = contains("auth", "token") || contains("auth", "status") && (options.flags["--show-token"] || options.flags["-t"]) || always
	case "make":
		printValue = makePrintsDatabase(args)
	case "npm", "pnpm", "yarn":
		lower := strings.ToLower(strings.Join(commands, " "))
		key := strings.Contains(lower, "token") || strings.Contains(lower, "auth") || strings.Contains(lower, "password") || strings.Contains(lower, "credential") || strings.Contains(lower, "secret")
		printValue = contains("config", "get") && key || contains("config", "list") && (name != "npm" || key || options.flags["--json"] || options.flags["-l"] || options.flags["--long"]) || name != "npm" && contains("config", "ls")
		always = name != "npm" && printValue
	case "kubectl":
		printValue = contains("create", "token") || contains("config", "view") && options.flags["--raw"]
		for _, resource := range commands {
			for _, kind := range strings.Split(resource, ",") {
				kind, _, _ = strings.Cut(kind, "/")
				for _, output := range options.outputs {
					format, _, _ := strings.Cut(output, "=")
					if (kind == "secret" || kind == "secrets") && contains("get") && kubectlContentFormat(format) {
						printValue, always = true, true
					}
				}
			}
		}
	case "gcloud":
		printValue = contains("config", "config-helper") || contains("auth", "print-access-token") || contains("auth", "print-identity-token")
	case "az":
		printValue = contains("account", "get-access-token") || contains("acr", "login") && hasOption(args, "--expose-token")
	case "heroku":
		printValue = contains("auth:token")
	case "vault":
		printValue = contains("print", "token") || contains("token", "lookup")
	case "doctl":
		printValue = contains("auth", "token")
	case "direnv":
		printValue = contains("export")
	case "aws":
		printValue = contains("ecr", "get-login-password") || contains("ecr-public", "get-login-password") || contains("ecr", "get-authorization-token") || contains("sso", "get-role-credentials") || contains("configure", "export-credentials")
		for _, action := range []string{"get-session-token", "assume-role", "assume-role-with-web-identity", "assume-role-with-saml", "get-federation-token"} {
			printValue = printValue || contains("sts", action)
		}
		lower := make([]string, len(commands))
		for i, word := range commands {
			lower[i] = strings.ToLower(word)
		}
		for _, key := range []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"} {
			printValue = printValue || orderedWords(lower, "configure", "get", key)
		}
	case "op":
		_, fields := options.values["--fields"]
		printValue = contains("read") || contains("item", "get") && (options.flags["--reveal"] || options.flags["--otp"] || fields) || contains("signin") && options.flags["--raw"]
	case "pass":
		if len(args) > 0 {
			switch arg(0) {
			case "ls", "list", "insert", "add", "edit", "generate", "rm", "remove", "delete", "mv", "rename", "cp", "copy", "init", "git", "help", "version":
			default:
				printValue = !strings.HasPrefix(arg(0), "-")
			}
		}
	case "secret-tool":
		action := printerAction(commands, "lookup search store clear lock")
		if action == "search" {
			return "secret-tool search prints secrets and is always denied"
		}
		printValue = action == "lookup"
	case "security":
		if contains("find-generic-password") || contains("find-internet-password") {
			if options.flags["-g"] {
				return "security -g prints passwords to stderr and is always denied"
			}
			printValue = options.flags["-w"]
		}
	case "kwallet-query":
		_, short := options.values["-r"]
		_, long := options.values["--read-password"]
		printValue = short || long
	case "docker", "docker-compose":
		if (name == "docker-compose" || contains("compose")) && (contains("config") || contains("convert")) {
			return "compose config prints env-file values"
		}
		if contains("inspect") && !(len(commands) > 0 && commands[0] == "image" && !options.unknownPrefix) {
			printValue = len(options.outputs) == 0
			for _, format := range options.outputs {
				printValue = printValue || format == "" || strings.EqualFold(format, "json") || strings.Contains(format, "Env") || strings.Contains(format, ".Config") || strings.Contains(format, "json .")
			}
		}
	case "php":
		printValue = options.flags["-i"] || options.flags["--info"]
		for _, option := range []string{"-r", "--run"} {
			code := options.values[option]
			printValue = printValue || strings.Contains(code, "phpinfo(") || (strings.Contains(code, "print_r(") || strings.Contains(code, "var_dump(")) && (strings.Contains(code, "$_SERVER") || strings.Contains(code, "$_ENV") || strings.Contains(code, "getenv("))
		}
		always = printValue // Keep the pre-normalizer PHP transport policy.
	case "ps":
		skip := false
		for _, a := range args {
			if skip {
				skip = false
				continue
			}
			switch a {
			case "-o", "o", "-O", "O", "--format", "-p", "p", "--pid", "-C", "-t", "t", "-u", "U", "-U", "-g", "-G":
				skip = true
				continue
			}
			if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" && strings.Contains(a, "e") || strings.HasPrefix(a, "-") && strings.Contains(a, "E") {
				printValue = true
			}
		}
	case "git":
		printValue = arg(0) == "credential" && arg(1) == "fill"
	case "export":
		printValue = len(args) == 0 || arg(0) == "-p"
	case "declare", "typeset":
		printValue = len(args) == 0
		for _, a := range args {
			if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a[1:], "xp") {
				printValue = true
			}
		}
	case "set":
		printValue = len(args) == 0
	case "echo", "printf":
		for _, a := range args {
			if credential.MatchString(a) {
				printValue = true
			}
		}
	case "jq", "yq":
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--arg", "--argjson":
				i += 2
				continue
			case "--rawfile", "--slurpfile":
				i += 2
				continue
			}
			a := args[i]
			if jqEnvironment.MatchString(a) {
				printValue = true
			}
		}

	}
	if printValue && (!direct || always) {
		return Printer
	}
	return ""
}

// OperandReason returns the guard's fixed reason for a protected input operand.
// The inputs callback checks only actual file operands, not prose or labels.
func OperandReason(name string, args []string, protected func(string) bool) string {
	if name == "grep" || name == "egrep" || name == "fgrep" {
		return GrepReason(args, protected)
	}
	if name == "sed" {
		return sedReason(args, protected)
	}
	if name == "split" {
		return splitReason(args, protected)
	}
	if name == "kubectl" && len(args) >= 4 && args[0] == "create" && args[1] == "secret" {
		return ""
	}
	if metadata[name] || name == "echo" || name == "printf" || name == "secret" || name == "tee" {
		return ""
	}
	if name == "docker" || name == "dotenv" {
		return ""
	}
	if name == "git" {
		i := 0
		for i < len(args) {
			a := args[i]
			if a == "-c" || a == "--config-env" {
				i++
				if i < len(args) && protected("./"+args[i]) {
					return "git config option names protected access"
				}
				i++
				continue
			}
			if strings.HasPrefix(a, "-c") && len(a) > 2 || strings.HasPrefix(a, "--config-env=") {
				if protected("./" + a) {
					return "git config option names protected access"
				}
				i++
				continue
			}
			if a == "-C" || a == "--work-tree" || a == "--git-dir" {
				i += 2
				continue
			}
			if strings.HasPrefix(a, "-") {
				i++
				continue
			}
			break
		}
		if i < len(args) {
			switch args[i] {
			case "check-ignore", "ls-files", "grep":
				return ""
			case "status":
				verbose := false
				for _, v := range args[i+1:] {
					if v == "--verbose" || v == "-v" {
						verbose = true
					}
				}
				if !verbose {
					return ""
				}
			}
			args = args[i+1:]
		}
	}
	if name == "du" || name == "file" {
		for i, v := range args {
			for _, opt := range []string{"--files0-from", "--exclude-from", "--files-from", "--magic-file"} {
				if v == opt && i+1 < len(args) && protected(args[i+1]) || strings.HasPrefix(v, opt+"=") && protected(strings.TrimPrefix(v, opt+"=")) {
					return name + " option reads a protected file"
				}
			}
			if (v == "-X" || v == "-f" || v == "-m") && i+1 < len(args) && protected(args[i+1]) || len(v) > 2 && (strings.HasPrefix(v, "-X") || strings.HasPrefix(v, "-f") || strings.HasPrefix(v, "-m")) && protected(v[2:]) {
				return name + " option reads a protected file"
			}
		}
		return ""
	}
	if name == "zip" && len(args) > 0 {
		args = args[1:]
	}
	if name == "dd" {
		for _, a := range args {
			if strings.HasPrefix(a, "if=") && protected(strings.TrimPrefix(a, "if=")) {
				return FileInput
			}
		}
		return ""
	}
	pattern := readers[name] && (name == "grep" || name == "rg" || name == "ag" || name == "sed" || name == "awk" || name == "gawk" || name == "jq" || name == "yq")
	end := len(args)
	if end > 1 {
		switch name {
		case "cp", "mv", "ln", "install", "rsync", "scp":
			targetOption := false
			for _, v := range args {
				if v == "-t" || v == "--target-directory" || strings.HasPrefix(v, "--target-directory=") || strings.HasPrefix(v, "-t") && len(v) > 2 {
					targetOption = true
				}
			}
			positional := 0
			for _, v := range args {
				if !strings.HasPrefix(v, "-") {
					positional++
				}
			}
			if !targetOption && positional >= 2 {
				end--
			}
		}
	}
	for i := 0; i < end; i++ {
		a := args[i]
		if name == "node" && a == "--env-file" {
			i++
			continue
		}
		if name == "node" && strings.HasPrefix(a, "--env-file=") {
			continue
		}
		if a == "--" {
			pattern = false
			continue
		}
		// Options carrying labels or output paths are not file inputs.
		if takesLabel(name, a) {
			i++
			continue
		}
		if name == "jq" && (a == "--rawfile" || a == "--slurpfile") {
			i++ // the binding name is a label, the following value is an input
			if i+1 < end && protected(args[i+1]) {
				return "jq file option targets a protected store"
			}
			i++
			continue
		}
		if name == "git" && strings.Contains(a, ":") && !strings.HasPrefix(a, "-") {
			a = "./" + strings.SplitN(a, ":", 2)[1]
		}
		if pattern && (strings.HasPrefix(a, "--regexp=") || strings.HasPrefix(a, "-e") && len(a) > 2) {
			pattern = false
			continue
		}
		if pattern && (a == "-e" || a == "--regexp") {
			i++
			pattern = false
			continue
		}
		if name == "jq" && (a == "--arg" || a == "--argjson") {
			i += 2
			continue
		}
		if a == "-f" || a == "--file" || a == "--files0-from" {
			pattern = false
			i++
			if i < end && protected(args[i]) {
				return "pattern file targets a protected store"
			}
			continue
		}
		if strings.HasPrefix(a, "--file=") || strings.HasPrefix(a, "--files0-from=") {
			pattern = false
			if protected(a[strings.IndexByte(a, '=')+1:]) {
				return "pattern file targets a protected store"
			}
			continue
		}
		if name == "openssl" && (a == "-in" || a == "-inkey") {
			i++
			if i < end && protected(args[i]) {
				return FileInput
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if pattern {
			pattern = false
			continue
		}

		if protected(a) {
			if readers[name] {
				return Reader
			}
			return FileInput
		}
	}
	return ""
}

// takesLabel identifies options whose next argument is metadata or an output path.
func takesLabel(name, option string) bool {
	switch name {
	case "git":
		return option == "-m" || option == "--message" || option == "--format" || option == "--pretty"
	case "cp", "mv", "ln":
		return option == "-S" || option == "--suffix" || option == "-t" || option == "--target-directory"
	case "split":
		return option == "-l" || option == "-b" || option == "-C" || option == "-n" || option == "-a"
	case "install":
		return option == "-m" || option == "-o" || option == "-g" || option == "-t"
	case "rsync":
		return option == "-e" || option == "--exclude" || option == "--include"
	case "scp":
		return option == "-P" || option == "-o"
	case "openssl":
		return option == "-out" || option == "-pass" || option == "-passin" || option == "-passout"
	case "gpg", "sops":
		return option == "-o" || option == "--output"
	}
	return false
}
