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
	case "env", "printenv", "pbpaste", "wl-paste":
		printValue = true
	case "xclip", "xsel":
		for _, a := range args {
			if a == "-o" || a == "--output" || a == "-out" {
				printValue = true
			}
		}
	case "gh":
		printValue = arg(0) == "auth" && arg(1) == "token"
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
		for _, a := range args {
			if strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" && strings.Contains(a, "e") && a != "" || strings.HasPrefix(a, "-") && strings.Contains(a, "E") {
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
			if strings.HasPrefix(a, "-x") || strings.HasPrefix(a, "-p") {
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
		for _, a := range args {
			if a == "env" || a == "$ENV" || strings.Contains(a, "$ENV") || strings.Contains(a, "env |") {
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
	if metadata[name] || name == "echo" || name == "printf" || name == "secret" {
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
				if i < len(args) && protected(args[i]) {
					return "git config option names protected access"
				}
				i++
				continue
			}
			if strings.HasPrefix(a, "-c") && len(a) > 2 || strings.HasPrefix(a, "--config-env=") {
				if protected(a) {
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
			case "check-ignore", "ls-files", "grep", "status":
				return ""
			}
			args = args[i+1:]
		}
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
			end--
		}
	}
	for i := 0; i < end; i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if a == "-f" || a == "--file" || a == "--files0-from" {
			i++
			if i < end && protected(args[i]) {
				return "pattern file targets a protected store"
			}
			continue
		}
		if strings.HasPrefix(a, "--file=") || strings.HasPrefix(a, "--files0-from=") {
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
