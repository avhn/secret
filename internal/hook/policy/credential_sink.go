package policy

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The credential must travel straight to stdin of a known password consumer.
// Literal argv is checked normally afterwards; substitutions, wrappers and
// alternate stdin cannot supply the proof for this exception.
func credentialSink(stmt *syntax.Stmt) bool {
	if stash(stmt) {
		return true
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 3 || len(call.Assigns) != 0 {
		return false
	}
	for _, redirect := range stmt.Redirs {
		if strings.HasPrefix(redirect.Op.String(), "<") {
			return false
		}
	}
	words := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		value := literal(word)
		if value == "" {
			return false
		}
		words = append(words, value)
	}
	args := words[1:]
	switch path.Base(words[0]) {
	case "docker":
		if args[0] != "login" {
			return false
		}
		args = args[1:]
	case "helm":
		if len(args) < 3 || args[0] != "registry" || args[1] != "login" {
			return false
		}
		args = args[2:]
	default:
		return false
	}
	stdin, options, registries := false, true, 0
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && arg == "--password-stdin" {
			stdin = true
			continue
		}
		if options && (arg == "--username" || arg == "-u") {
			i++
			if i == len(args) {
				return false
			}
			continue
		}
		if options && (strings.HasPrefix(arg, "--username=") || strings.HasPrefix(arg, "-u") && len(arg) > 2) {
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			return false
		}
		registries++
	}
	return stdin && registries <= 1
}
