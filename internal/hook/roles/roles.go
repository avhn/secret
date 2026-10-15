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
	Printer       = "credential printer requires a direct pipe to secret stash FILE KEY"
	Indeterminate = "command too complex to analyse for secret access; split it or use secret run"
)

var jqEnvironment = regexp.MustCompile(`(^|[^A-Za-z0-9_."'])(env|\$ENV)([^A-Za-z0-9_]|$)`)

var readers = map[string]bool{}
var metadata = map[string]bool{}
var credential = regexp.MustCompile(`(?i)\$\{?[a-z0-9_]*(token|secret|pass(word|wd)?|api_?key|private_key|credential|_key)[a-z0-9_]*\}?`)

func init() {
	for _, name := range strings.Fields("cat bat less more head tail grep egrep fgrep rg ag sed awk gawk perl python python3 ruby node source . xxd od hexdump strings cut sort uniq base64 jq yq tr nl tac rev diff cmp vim vi nvim nano emacs pbcopy open wc") {
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
// stdout pipe is permitted only when the sink is a validated secret stash.
func PrinterReason(name string, args []string, direct bool) string {
	arg := func(n int) string {
		if n < len(args) {
			return args[n]
		}
		return ""
	}
	printValue := false
	switch name {
	case "env", "printenv", "pbpaste", "wl-paste", "envsubst":
		printValue = true
	case "xclip", "xsel":
		for _, a := range args {
			if a == "-o" || a == "--output" || a == "-out" {
				printValue = true
			}
		}
	case "gh":
		printValue = arg(0) == "auth" && arg(1) == "token"
		if arg(0) == "auth" && arg(1) == "status" {
			for _, v := range args[2:] {
				if v == "--show-token" || v == "-t" {
					printValue = true
				}
			}
		}
	case "make":
		for _, v := range args {
			if v == "--print-data-base" || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.Contains(v, "p") {
				printValue = true
			}
		}
	case "npm":
		if arg(0) == "config" {
			lower := strings.ToLower(strings.Join(args[2:], " "))
			key := strings.Contains(lower, "token") || strings.Contains(lower, "auth") || strings.Contains(lower, "password")
			printValue = arg(1) == "get" && key || arg(1) == "list" && (key || strings.Contains(lower, "--json") || strings.Contains(" "+lower+" ", " -l "))
		}
	case "kubectl":
		if arg(0) == "config" && arg(1) == "view" {
			for _, v := range args[2:] {
				if v == "--raw" || v == "--raw=true" {
					printValue = true
				}
			}
		}
	case "gcloud":
		j := 0
		if arg(j) == "auth" {
			j++
			if arg(j) == "application-default" {
				j++
			}
			printValue = arg(j) == "print-access-token" || arg(j) == "print-identity-token"
		}
	case "aws":
		filtered := make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if args[i] == "--profile" {
				i++
				continue
			}
			if strings.HasPrefix(args[i], "--profile=") {
				continue
			}
			filtered = append(filtered, args[i])
		}
		if len(filtered) >= 2 && filtered[0] == "configure" {
			printValue = filtered[1] == "export-credentials"
			if filtered[1] == "get" && len(filtered) > 2 {
				switch strings.ToLower(filtered[2]) {
				case "aws_access_key_id", "aws_secret_access_key", "aws_session_token":
					printValue = true
				}
			}
		}
	case "op":
		printValue = arg(0) == "read"
		if arg(0) == "item" && arg(1) == "get" {
			for _, a := range args[2:] {
				if a == "--reveal" || a == "--fields" || strings.HasPrefix(a, "--fields=") {
					printValue = true
				}
			}
		}
	case "pass":
		if len(args) > 0 {
			switch arg(0) {
			case "ls", "list", "insert", "add", "edit", "generate", "rm", "remove", "delete", "mv", "rename", "cp", "copy", "init", "git", "help", "version":
			default:
				printValue = !strings.HasPrefix(arg(0), "-")
			}
		}
	case "secret-tool":
		if arg(0) == "search" {
			return "secret-tool search prints secrets and is always denied"
		}
		printValue = arg(0) == "lookup"
	case "security":
		if arg(0) == "find-generic-password" || arg(0) == "find-internet-password" {
			for _, a := range args[1:] {
				if a == "-g" {
					return "security -g prints passwords to stderr and is always denied"
				}
				if a == "-w" {
					printValue = true
				}
			}
		}
	case "kwallet-query":
		for _, a := range args {
			if a == "-r" || a == "--read-password" || strings.HasPrefix(a, "--read-password=") {
				printValue = true
			}
		}
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
	if printValue && !direct {
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
