// Package policy analyses bounded Bash syntax without running shell code.
package policy

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"github.com/avhn/secret/internal/hook/search"
	"mvdan.cc/sh/v3/syntax"
)

var ErrIndeterminate = errors.New("indeterminate shell command")

// Analyze returns a fixed denial reason, or an empty reason for an allowed
// command. Unsupported content-producing syntax is not treated as safe.
func Analyze(source, cwd, home string, protected func(string, string) bool) string {
	// The legacy guard treats named protected content in long shell text as
	// indeterminate. Keep that stricter boundary even when parsing can proceed.
	if len(source) > 8192 && (longPrinter(source) || longProtected(source)) {
		return roles.Indeterminate
	}
	// A deeply nested literal -c chain can hide shell code behind repeated
	// shell-quote boundaries. Never let it outlive the recursion budget.
	if strings.Count(source, "bash -c")+strings.Count(source, "sh -c") > 4 && (witness(source) || riskyRole(source)) {
		return roles.Indeterminate
	}
	a := &analyzer{protected: protected, cwd: cwd, home: home, deadline: time.Now().Add(2 * time.Second)}
	a.fragment(source, 0)
	if a.reason != "" {
		return a.reason
	}
	if a.uncertain && (witness(source) || riskyRole(source)) {
		return roles.Indeterminate
	}
	return ""
}

// AnalyzeArgv checks already-tokenized host arguments without joining them
// into shell source. Only explicit bash/sh -c source is parsed as shell code.
func AnalyzeArgv(argv []string, cwd, home string, protected func(string, string) bool) string {
	if len(argv) == 0 || len(argv) > 128 {
		return roles.Indeterminate
	}
	for _, arg := range argv {
		if len(arg) > 40<<10 {
			return roles.Indeterminate
		}
	}
	a := &analyzer{protected: protected, cwd: cwd, home: home, deadline: time.Now().Add(2 * time.Second)}
	a.command(argv, 0, cwd, false)
	if a.reason != "" {
		return a.reason
	}
	if a.uncertain && (witness(strings.Join(argv, " ")) || riskyRole(strings.Join(argv, " "))) {
		return roles.Indeterminate
	}
	return ""
}

type analyzer struct {
	protected         func(string, string) bool
	cwd, home, reason string
	words, globs      int
	uncertain         bool
	deadline          time.Time
}

func witness(source string) bool {
	s := strings.ToLower(source)
	for _, v := range []string{".env", ".secret", ".secrets", ".netrc", ".npmrc", ".pypirc", ".aws/credentials", ".docker/config.json", ".config/gh/hosts.yml", ".git-credentials", ".ssh/id_", "/environ", "secret-tool", "printenv", "gh auth token", "$token", "$password", "$secret"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	for _, phrase := range []string{"security find-", "git credential fill", "secret get", "secret exec", "pbpaste", "wl-paste", "rg ", "git grep", "env ", "bash -c", "gh auth token", "gcloud auth print-", "aws configure get aws_", "aws configure export-credentials", "op read", "op item get", "pass show", "secret-tool lookup", "kwallet-query -r", "ps e", "jq -n env"} {
		if strings.Contains(s, phrase) {
			return true
		}
	}
	return strings.Contains(s, ".en*") || strings.Contains(s, ".en{") || strings.Contains(s, ".{env")
}

// longProtected retains the stricter legacy treatment for protected path
// witnesses in long source without treating public suffixes as private files.
func longProtected(source string) bool {
	before := strings.SplitN(source, " # ", 2)[0]
	fields := strings.Fields(before)
	if len(fields) > 0 && strings.EqualFold(fields[0], "ENV") {
		return true
	}
	for _, field := range fields {
		item := strings.Trim(field, "'\";|&(){}<>")
		lower := strings.ToLower(item)
		if lower == ".env" || strings.HasPrefix(lower, ".env.") && !strings.HasSuffix(lower, ".example") && !strings.HasSuffix(lower, ".template") || strings.Contains(lower, ".ssh/id_") && !strings.HasSuffix(lower, ".pub") || strings.Contains(lower, ".npmrc\\") || strings.Contains(lower, "*.secret") {
			return true
		}
	}
	return false
}

// longPrinter catches bare printers whose role is lost behind a long comment.
func longPrinter(source string) bool {
	for _, cmd := range strings.Split(source, ";") {
		fields := strings.Fields(strings.ToLower(strings.SplitN(cmd, "#", 2)[0]))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "compgen", "xclip", "xsel", "rg":
			return true
		}
	}
	return false
}

// riskyRole is for parser and budget failures only. It cannot certify shell
// words, so a possible reader or printer is never treated as an inert command.
func riskyRole(source string) bool {
	for _, field := range strings.Fields(source) {
		name := strings.Trim(field, "'\";|&(){}<> ")
		if roles.KnownReader(name) || roles.PrinterReason(name, nil, false) != "" {
			return true
		}
	}
	return false
}
func (a *analyzer) fragment(source string, depth int) {
	if a.reason != "" {
		return
	}
	if len(source) > 40<<10 || depth > 4 || time.Now().After(a.deadline) {
		a.uncertain = true
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		a.uncertain = true
		return
	}
	a.stmts(file.Stmts, depth, a.cwd)
}
func (a *analyzer) stmts(stmts []*syntax.Stmt, depth int, cwd string) string {
	if depth > 4 || time.Now().After(a.deadline) {
		a.uncertain = true
		return cwd
	}
	for _, s := range stmts {
		if a.reason != "" {
			break
		}
		for _, r := range s.Redirs {
			a.walkWord(r.Word, depth, cwd)
			a.walkWord(r.Hdoc, depth, cwd)
			op := r.Op.String()
			if strings.HasPrefix(op, "<") || op == "<>" {
				if a.protectedWord(r.Word, cwd) {
					a.reason = "input redirect reads a protected store"
				}
			}
		}
		switch cmd := s.Cmd.(type) {
		case *syntax.CallExpr:
			if len(cmd.Args) == 0 {
				for _, assign := range cmd.Assigns {
					a.walkWord(assign.Value, depth, cwd)
				}
				continue
			}
			for _, assign := range cmd.Assigns {
				a.walkWord(assign.Value, depth, cwd)
			}
			words := make([]string, 0, len(cmd.Args))
			unknown := false
			for idx, w := range cmd.Args {
				if cmd.Args[0].Lit() == "jq" && a.raw(w) == `"$ENV"` {
					words = append(words, "$ENV")
					continue
				}
				if idx == 0 && w.Lit() == "[" {
					words = append(words, "[")
					continue
				}
				// jq --arg binds a literal filter variable without reading a file.
				if cmd.Args[0].Lit() == "jq" && a.raw(w) == `"$label"` {
					bound := false
					for j := 1; j+2 < idx; j++ {
						if cmd.Args[j].Lit() == "--arg" && cmd.Args[j+1].Lit() == "label" {
							bound = true
						}
					}
					if bound {
						words = append(words, "$label")
						continue
					}
				}
				a.walkWord(w, depth, cwd)
				values, ok := a.expandWord(w, cwd)
				if !ok {
					unknown = true
					words = append(words, "")
					continue
				}
				words = append(words, values...)
			}
			if a.reason != "" {
				break
			}
			if len(words) > 0 && words[0] == "" && len(cmd.Args) > 0 && a.raw(cmd.Args[0]) == "[" {
				words[0] = "["
			}
			if len(words) == 0 {
				a.uncertain = true
				break
			}
			name := path.Base(words[0])
			args := words[1:]
			if name == "cd" {
				if len(args) > 0 && !unknown {
					cwd = a.resolve(args[0], cwd)
				} else {
					a.uncertain = true
				}
				continue
			}
			if name == "secret" {
				if len(args) == 0 {
					a.reason = "secret get/exec or unknown subcommand is not an agent transport"
					continue
				}
				switch args[0] {
				case "list", "show", "stash", "clip", "help", "--help", "-h":
					continue
				case "run":
					for i, v := range args {
						if v == "--" && i+1 < len(args) {
							a.command(args[i+1:], depth+1, cwd, false)
							break
						}
					}
					continue
				default:
					a.reason = "secret get/exec or unknown subcommand is not an agent transport"
					continue
				}
			}
			direct := false
			// Pipe validation is handled by the containing binary command.
			if strings.HasPrefix(name, "python") || name == "perl" || name == "ruby" || name == "node" {
				skip := false
				for _, w := range cmd.Args[1:] {
					code := a.raw(w)
					if name == "node" {
						if skip {
							skip = false
							continue
						}
						if code == "--env-file" {
							skip = true
							continue
						}
						if strings.HasPrefix(code, "--env-file=") {
							continue
						}
					}
					if witness(code) || strings.Contains(code, "ENV") || strings.Contains(strings.ToLower(code), "getenv") || strings.Contains(code, ".environ") || strings.Contains(code, "process.env") {
						a.reason = "interpreter argument names a protected file or credential operation"
						break
					}
				}
			}
			if unknown && (name == "echo" || name == "printf") && roles.CredentialExpansion(a.rawArgs(cmd.Args)) {
				a.reason = roles.Printer
			}
			if a.reason == "" {
				for _, assign := range cmd.Assigns {
					if name == "rg" && assign.Name != nil && assign.Name.Value == "RIPGREP_CONFIG_PATH" {
						a.reason = "rg config cannot establish safe search inputs"
					}
				}
				if a.reason == "" {
					a.command(words, depth, cwd, direct)
				}
			}
			if unknown && roles.Reading(name) && a.reason == "" && !(name == "jq" && strings.Contains(a.rawArgs(cmd.Args), `"$label"`) && !roles.CredentialExpansion(a.rawArgs(cmd.Args))) {
				a.reason = roles.Indeterminate
			}
		case *syntax.BinaryCmd:
			if cmd.Op.String() == "|" && stash(cmd.Y) && !stdoutRedirect(cmd.X) {
				if decl, ok := cmd.X.Cmd.(*syntax.DeclClause); ok {
					for _, assign := range decl.Args {
						a.walkWord(assign.Value, depth, cwd)
					}
					if a.reason != "" {
						break
					}
					if reason := roles.PrinterReason(decl.Variant.Value, nil, true); reason != "" {
						a.reason = reason
					}
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
					break
				}
			}
			if cmd.Op.String() == "|" && a.xargsListing(cmd.X, cmd.Y, cwd) {
				a.reason = "xargs reader consumes a protected-name listing"
				break
			}
			if cmd.Op.String() == "|" && stash(cmd.Y) && !stdoutRedirect(cmd.X) {
				a.printerPipe(cmd.X, depth, cwd)
				if a.reason == "" {
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
				}
			} else {
				leftCWD := a.stmts([]*syntax.Stmt{cmd.X}, depth, cwd)
				if cmd.Op.String() == "&&" {
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, leftCWD)
				} else {
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
				}
			}
		case *syntax.Subshell:
			a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.Block:
			cwd = a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.FuncDecl:
			a.stmts([]*syntax.Stmt{cmd.Body}, depth, cwd)
		case *syntax.IfClause:
			for clause := cmd; clause != nil; clause = clause.Else {
				a.stmts(clause.Cond, depth, cwd)
				a.stmts(clause.Then, depth, cwd)
			}
		case *syntax.WhileClause:
			a.stmts(cmd.Cond, depth, cwd)
			a.stmts(cmd.Do, depth, cwd)
		case *syntax.ForClause:
			a.stmts(cmd.Do, depth, cwd)
			a.uncertain = true
		case *syntax.CaseClause:
			a.walkWord(cmd.Word, depth, cwd)
			for _, item := range cmd.Items {
				a.stmts(item.Stmts, depth, cwd)
			}
			a.uncertain = true
		case *syntax.DeclClause:
			args := make([]string, 0, len(cmd.Args))
			for _, assign := range cmd.Args {
				if assign.Value != nil {
					args = append(args, a.raw(assign.Value))
				} else if assign.Name != nil {
					args = append(args, assign.Name.Value)
				}
			}
			if reason := roles.PrinterReason(cmd.Variant.Value, args, false); reason != "" {
				a.reason = reason
			}
		case *syntax.TestClause:
			syntax.Walk(cmd, func(node syntax.Node) bool {
				if nested, ok := node.(*syntax.CmdSubst); ok {
					a.stmts(nested.Stmts, depth+1, cwd)
					return false
				}
				return true
			})
		case *syntax.ArithmCmd:
			a.uncertain = true
		default:
			a.uncertain = true
		}
	}
	return cwd
}

// xargsListing checks only an AST-connected stdout pipe into a reader.
// It never relies on the printed output of an upstream command.
func (a *analyzer) xargsListing(upstream, downstream *syntax.Stmt, cwd string) bool {
	call, ok := downstream.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 || call.Args[0].Lit() != "xargs" {
		return false
	}
	reader := false
	for _, w := range call.Args[1:] {
		if roles.Reading(path.Base(w.Lit())) && w.Lit() != "" {
			reader = true
		}
	}
	if !reader {
		return false
	}
	return a.listingWitness(upstream, cwd)
}

func (a *analyzer) listingWitness(stage *syntax.Stmt, cwd string) bool {
	if pipe, ok := stage.Cmd.(*syntax.BinaryCmd); ok && pipe.Op.String() == "|" {
		return a.listingWitness(pipe.X, cwd) || a.listingWitness(pipe.Y, cwd)
	}
	if source, ok := stage.Cmd.(*syntax.CallExpr); ok {
		for _, w := range source.Args[1:] {
			if a.protectedWord(w, cwd) || a.uncertain || witness(a.raw(w)) {
				return true
			}
		}
	}
	return false
}

var stashEnv = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
var stashLabel = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// stash accepts only a direct secret stash sink with validated options.
// Redirects on the sink do not divert the printer's stdout from the pipe.
func stash(s *syntax.Stmt) bool {
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 4 {
		return false
	}
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if w.Lit() == "" {
			return false
		}
		words = append(words, w.Lit())
	}
	if path.Base(words[0]) != "secret" || words[1] != "stash" {
		return false
	}
	i := 2
	for i < len(words)-2 {
		switch words[i] {
		case "--env", "--label":
			if i+1 >= len(words)-2 {
				return false
			}
			re := stashEnv
			if words[i] == "--label" {
				re = stashLabel
			}
			if !re.MatchString(words[i+1]) {
				return false
			}
			i += 2
		default:
			var re *regexp.Regexp
			var value string
			if strings.HasPrefix(words[i], "--env=") {
				re, value = stashEnv, strings.TrimPrefix(words[i], "--env=")
			}
			if strings.HasPrefix(words[i], "--label=") {
				re, value = stashLabel, strings.TrimPrefix(words[i], "--label=")
			}
			if re == nil || !re.MatchString(value) {
				return false
			}
			i++
		}
	}
	return i == len(words)-2 && words[i] != "" && words[i+1] != ""
}

// sudoOptionValue identifies options whose next word belongs to sudo, not its child.
func sudoOptionValue(option string) bool {
	switch option {
	case "-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "--user", "--group", "--host", "--prompt", "--close-from", "--chdir", "--chroot", "--command-timeout", "--other-user":
		return true
	}
	return false
}

// sudoOptionAttached recognises an inline option operand.
func sudoOptionAttached(option string) bool {
	if strings.HasPrefix(option, "--") {
		for _, prefix := range []string{"--user=", "--group=", "--host=", "--prompt=", "--close-from=", "--chdir=", "--chroot=", "--command-timeout=", "--other-user="} {
			if strings.HasPrefix(option, prefix) {
				return true
			}
		}
		return false
	}
	return len(option) > 2 && strings.ContainsRune("ughpCDRTU", rune(option[1]))
}

// sudoFlag lists switches which consume no child operand.
func sudoFlag(option string) bool {
	switch option {
	case "-A", "-b", "-E", "-H", "-K", "-k", "-l", "-n", "-P", "-S", "-V", "-v", "--askpass", "--background", "--preserve-env", "--set-home", "--reset-timestamp", "--remove-timestamp", "--list", "--non-interactive", "--preserve-groups", "--stdin", "--version", "--validate", "--help":
		return true
	}
	return false
}

// stdoutRedirect rejects any upstream redirect that can divert stdout.
func stdoutRedirect(s *syntax.Stmt) bool {
	for _, r := range s.Redirs {
		fd := "1"
		if r.N != nil {
			fd = r.N.Value
		}
		if fd == "1" || fd == "01" || fd == "" {
			if strings.Contains(r.Op.String(), ">") {
				return true
			}
		}
	}
	return false
}
func (a *analyzer) printerPipe(s *syntax.Stmt, depth int, cwd string) {
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok {
		a.stmts([]*syntax.Stmt{s}, depth, cwd)
		return
	}
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if call.Args[0].Lit() == "jq" && a.raw(w) == `"$ENV"` {
			words = append(words, "$ENV")
			continue
		}
		a.walkWord(w, depth, cwd)
		v, ok := a.expandWord(w, cwd)
		if !ok {
			a.uncertain = true
			return
		}
		words = append(words, v...)
	}
	if len(words) > 0 {
		a.command(words, depth, cwd, true)
	}
}
func (a *analyzer) command(words []string, depth int, cwd string, direct bool) {
	if len(words) == 0 || a.reason != "" {
		return
	}
	name := path.Base(words[0])
	args := words[1:]
	if name == "[" || name == "[[" {
		return
	}
	for _, arg := range args {
		if arg == "--unrecognised" && (witness(strings.Join(args, " ")) || strings.Contains(" "+strings.Join(args, " ")+" ", " env ")) {
			a.reason = roles.Indeterminate
			return
		}
	}
	if name == "grep" || name == "egrep" || name == "fgrep" {
		for _, arg := range args {
			if arg == "--recursive" || arg == "--dereference-recursive" || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "rR") {
				a.reason = "recursive grep bypasses protected search defaults; use plain rg"
				return
			}
		}
	}
	switch name {
	case "find":
		selected := false
		for i, v := range args {
			if (v == "-name" || v == "-iname" || v == "-path" || v == "-regex") && i+1 < len(args) && witness(args[i+1]) {
				selected = true
			}
		}
		for i, v := range args {
			if v == "-files0-from" && i+1 < len(args) && a.protected(args[i+1], cwd) || strings.HasPrefix(v, "-files0-from=") && a.protected(strings.TrimPrefix(v, "-files0-from="), cwd) {
				a.reason = "find reads a protected name list"
				return
			}
			if v == "-exec" || v == "-execdir" || v == "-ok" || v == "-okdir" {
				end := i + 1
				for end < len(args) && args[end] != ";" && args[end] != "+" {
					end++
				}
				if end <= i+1 {
					a.reason = roles.Indeterminate
					return
				}
				child := append([]string(nil), args[i+1:end]...)
				if selected && len(child) > 2 && (child[0] == "sh" || child[0] == "bash") && (strings.Contains(child[2], "$1") || strings.Contains(child[2], "${1}")) {
					a.reason = roles.Indeterminate
					return
				}
				if selected {
					for j := range child {
						if child[j] == "{}" {
							child[j] = ".env"
						}
					}
				}
				a.command(child, depth+1, cwd, false)
				if a.reason != "" {
					return
				}
			}
		}
		return
	case "bash", "sh", "zsh", "eval":
		if name == "eval" {
			if len(args) > 0 {
				a.fragment(strings.Join(args, " "), depth+1)
			}
			return
		}
		for i, v := range args {
			if (v == "-c" || v == "-lc" || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.Contains(v, "c")) && i+1 < len(args) {
				a.fragment(args[i+1], depth+1)
				return
			}
		}
	case "env", "sudo", "nice", "timeout", "nohup", "exec", "command", "builtin", "stdbuf", "caffeinate":
		if name == "nice" && len(args) > 2 && args[0] == "-n" {
			a.command(args[2:], depth+1, cwd, direct)
			return
		}
		if name == "sudo" {
			shell := false
			for len(args) > 0 && strings.HasPrefix(args[0], "-") {
				option := args[0]
				if option == "--" {
					args = args[1:]
					break
				}
				if option == "-s" || option == "-i" || option == "--shell" || option == "--login" {
					shell = true
					args = args[1:]
					continue
				}
				if sudoOptionValue(option) {
					if len(args) < 2 {
						return
					}
					args = args[2:]
					continue
				}
				if sudoOptionAttached(option) || sudoFlag(option) {
					args = args[1:]
					continue
				}
				a.uncertain = true
				return
			}
			if len(args) == 0 {
				return
			}
			if shell && len(args) == 1 {
				a.fragment(args[0], depth+1)
				return
			}
			a.command(args, depth+1, cwd, direct)
			return
		}
		if name == "timeout" {
			for i, v := range args {
				if v == "--signal" || v == "--kill-after" {
					continue
				}
				if !strings.HasPrefix(v, "-") && i+1 < len(args) {
					a.command(args[i+1:], depth+1, cwd, direct)
					return
				}
			}
		}
		if name == "env" {
			// Split-string supplies child words, not an environment dump.
			if len(args) >= 2 && (args[0] == "-S" || args[0] == "--split-string") {
				if args[1] == "echo" {
					a.command(args[1:], depth+1, cwd, direct)
					return
				}
				code := "env " + args[1]
				for _, arg := range args[2:] {
					code += " " + strconv.Quote(arg)
				}
				a.fragment(code, depth+1)
				return
			}
			if len(args) > 0 && (strings.HasPrefix(args[0], "--split-string=") || strings.HasPrefix(args[0], "-S") && len(args[0]) > 2) {
				code := strings.TrimPrefix(args[0], "--split-string=")
				if strings.HasPrefix(args[0], "-S") {
					code = args[0][2:]
				}
				a.fragment("env "+code, depth+1)
				return
			}
			// Strip only known option operands, then analyze the actual child.
			for len(args) > 0 {
				switch args[0] {
				case "-u", "--unset", "-C", "--chdir":
					if len(args) < 2 {
						a.reason = roles.Indeterminate
						return
					}
					if args[0] == "-C" || args[0] == "--chdir" {
						cwd = a.resolve(args[1], cwd)
					}
					args = args[2:]
				case "-i", "--ignore-environment", "-0", "--null":
					args = args[1:]
				default:
					if strings.HasPrefix(args[0], "-") && args[0] != "--" && !strings.HasPrefix(args[0], "--unset=") && !strings.HasPrefix(args[0], "--chdir=") {
						a.reason = roles.Indeterminate
						return
					}
					if strings.HasPrefix(args[0], "--chdir=") {
						cwd = a.resolve(strings.TrimPrefix(args[0], "--chdir="), cwd)
						args = args[1:]
						continue
					}
					if strings.HasPrefix(args[0], "--unset=") {
						args = args[1:]
						continue
					}
					goto envChild
				}
			}
		envChild:
			if len(args) == 0 {
				a.reason = roles.Printer
				return
			}
		}
		for i, v := range args {
			if v == "--" {
				a.command(args[i+1:], depth+1, cwd, direct)
				return
			}
			if !strings.HasPrefix(v, "-") && !strings.Contains(v, "=") {
				if name == "timeout" || name == "nice" && v == "-n" {
					continue
				}
				a.command(args[i:], depth+1, cwd, direct)
				return
			}
		}
		if name == "env" {
			a.reason = roles.Printer
		}
		return
	case "docker", "dotenv":
		for _, v := range args {
			if name == "dotenv" && (v == "-p" || v == "--print") {
				a.reason = "dotenv prints an environment value"
				return
			}
			if v == "--entrypoint" || strings.HasPrefix(v, "--entrypoint=") {
				a.reason = roles.Indeterminate
				return
			}
		}
		for _, v := range args {
			if v == "env" || v == "printenv" {
				a.reason = roles.Printer
				return
			}
			if v == "config" && name == "docker" && strings.Contains(strings.Join(args, " "), "--env-file") {
				a.reason = "compose config prints env-file values"
				return
			}
		}
		return
	case "xargs":
		for i, v := range args {
			if (v == "-a" || v == "--arg-file") && i+1 < len(args) && a.protected(args[i+1], cwd) || strings.HasPrefix(v, "-a") && len(v) > 2 && a.protected(v[2:], cwd) || strings.HasPrefix(v, "--arg-file=") && a.protected(strings.TrimPrefix(v, "--arg-file="), cwd) {
				a.reason = "xargs arg-file reads a protected store"
				return
			}
			if !strings.HasPrefix(v, "-") {
				a.command(args[i:], depth+1, cwd, false)
				return
			}
		}
		return
	}
	if name == "rg" || name == "git" {
		// Nested wrappers cannot inherit the hook's rg config certification.
		a.reason = search.Scope(words, cwd, a.home, os.Getenv("RIPGREP_CONFIG_PATH"), depth > 0 || cwd != a.cwd && os.Getenv("RIPGREP_CONFIG_PATH") != "" && !path.IsAbs(os.Getenv("RIPGREP_CONFIG_PATH")) || strings.Contains(strings.Join(words, " "), "RIPGREP_CONFIG_PATH"))
		if a.reason == search.ScopeReason {
			a.reason = search.UncertainReason
		}
		if a.reason != "" {
			return
		}
	}
	if reason := roles.PrinterReason(name, args, direct); reason != "" {
		a.reason = reason
		return
	}
	operandCWD := cwd
	if name == "git" || name == "tar" {
		for i, v := range args {
			if (v == "-C" || v == "--directory") && i+1 < len(args) {
				operandCWD = a.resolve(args[i+1], operandCWD)
			}
			if strings.HasPrefix(v, "--directory=") {
				operandCWD = a.resolve(strings.TrimPrefix(v, "--directory="), operandCWD)
			}
		}
	}
	if name == "tar" {
		create := false
		for _, v := range args {
			if v == "-c" || v == "--create" || len(v) > 1 && v[0] == '-' && strings.Contains(v[1:], "c") {
				create = true
			}
		}
		if len(args) > 0 && strings.HasPrefix(args[0], "c") {
			create = true
		}
		for i, v := range args {
			if create && i == 0 && strings.HasPrefix(v, "c") && strings.Contains(v, "f") && len(args) > 1 {
				args = append(args[:1], args[2:]...)
				break
			}
			if create && (v == "-f" || v == "--file" || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.HasSuffix(v, "f")) && i+1 < len(args) {
				args = append(args[:i+1], args[i+2:]...)
				break
			}
		}
		for i, v := range args {
			if v == "-f" || v == "--file" {
				if !create && i+1 < len(args) && a.protected(args[i+1], operandCWD) {
					a.reason = roles.FileInput
					return
				}
			}
			if !create && strings.HasPrefix(v, "--file=") && a.protected(strings.TrimPrefix(v, "--file="), operandCWD) {
				a.reason = roles.FileInput
				return
			}
			if !create && strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.Contains(v, "f") {
				if file := v[strings.IndexByte(v, 'f')+1:]; file != "" && a.protected(file, operandCWD) {
					a.reason = roles.FileInput
					return
				}
			}
		}
	}
	if reason := roles.OperandReason(name, args, func(path string) bool { return a.protected(path, operandCWD) }); reason != "" {
		a.reason = reason
	}
}
func (a *analyzer) resolve(name, cwd string) string {
	if strings.HasPrefix(name, "~/") {
		name = path.Join(a.home, name[2:])
	}
	if path.IsAbs(name) {
		return path.Clean(name)
	}
	return path.Join(cwd, name)
}

func (a *analyzer) protectedWord(w *syntax.Word, cwd string) bool {
	values, ok := a.expandWord(w, cwd)
	if !ok {
		a.uncertain = true
		return true
	}
	for _, v := range values {
		if a.protected(v, cwd) {
			return true
		}
	}
	return false
}
func (a *analyzer) raw(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	syntax.NewPrinter().Print(&b, w)
	return b.String()
}
func (a *analyzer) rawArgs(ws []*syntax.Word) string {
	var b strings.Builder
	for _, w := range ws {
		b.WriteString(a.raw(w))
		b.WriteByte(' ')
	}
	return b.String()
}
func (a *analyzer) walkWord(w *syntax.Word, depth int, cwd string) {
	if w == nil {
		return
	}
	syntax.Walk(w, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CmdSubst:
			a.stmts(n.Stmts, depth+1, cwd)
			return false
		case *syntax.ProcSubst:
			a.stmts(n.Stmts, depth+1, cwd)
			return false
		}
		return true
	})
}

// expandWord deliberately avoids expand.Fields: its default expander can read
// ambient variables, execute substitutions, and enumerate the filesystem.
func (a *analyzer) expandWord(w *syntax.Word, cwd string) ([]string, bool) {
	a.words++
	if a.words > 128 || time.Now().After(a.deadline) {
		a.uncertain = true
		return nil, false
	}
	if w == nil {
		return nil, true
	}
	for _, part := range w.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.Count(lit.Value, "{") > strings.Count(lit.Value, "}") {
			a.uncertain = true
			return nil, false
		}
	}
	syntax.SplitBraces(w)
	// Never pass SplitBraces results to syntax.Walk: this parser version
	// panics on BraceExp nodes, which are introduced by SplitBraces itself.
	return a.literalWord(w, cwd)
}
func (a *analyzer) literalWord(w *syntax.Word, cwd string) ([]string, bool) {
	result := []string{""}
	unquotedGlob := false
	for _, part := range w.Parts {
		var piece string
		switch n := part.(type) {
		case *syntax.Lit:
			piece = strings.ReplaceAll(n.Value, `\`, ``)
			if strings.Contains(piece, "{") && (strings.Contains(piece, ",") || strings.Contains(piece, "..")) {
				a.uncertain = true
				return nil, false
			}
			unquotedGlob = unquotedGlob || strings.ContainsAny(piece, "*?[")
		case *syntax.SglQuoted:
			piece = n.Value
			if n.Dollar {
				var err error
				piece, err = strconv.Unquote("\"" + strings.ReplaceAll(n.Value, "\"", "\\\"") + "\"")
				if err != nil {
					a.uncertain = true
					return nil, false
				}
			}
		case *syntax.DblQuoted:
			for _, child := range n.Parts {
				switch x := child.(type) {
				case *syntax.Lit:
					piece += x.Value
				case *syntax.ParamExp:
					if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
						a.uncertain = true
						return nil, false
					}
					if x.Param.Value == "HOME" && a.home != "" {
						piece += a.home
					} else {
						a.uncertain = true
						return nil, false
					}
				default:
					a.uncertain = true
					return nil, false
				}
			}
		case *syntax.ParamExp:
			if n.Param == nil || n.Exp != nil || n.Repl != nil || n.Slice != nil || n.Index != nil || n.Length || n.Excl {
				a.uncertain = true
				return nil, false
			}
			if n.Param.Value == "HOME" && a.home != "" {
				piece = a.home
			} else {
				a.uncertain = true
				return nil, false
			}
		case *syntax.BraceExp:
			if n.Sequence || len(n.Elems) > 64 || len(result)*len(n.Elems) > 64 {
				a.uncertain = true
				return nil, false
			}
			next := make([]string, 0, len(result)*len(n.Elems))
			for _, prefix := range result {
				for _, elem := range n.Elems {
					values, ok := a.literalWord(elem, cwd)
					if !ok {
						return nil, false
					}
					for _, v := range values {
						next = append(next, prefix+v)
						if len(next) > 64 {
							a.uncertain = true
							return nil, false
						}
					}
				}
			}
			result = next
			continue
		default:
			a.uncertain = true
			return nil, false
		}
		for i := range result {
			result[i] += piece
		}
	}
	expanded := make([]string, 0, len(result))
	for _, v := range result {
		if strings.HasPrefix(v, "~/") {
			v = path.Join(a.home, v[2:])
		}
		if unquotedGlob && strings.ContainsAny(v, "*?[") {
			for _, candidate := range []string{".env", ".env.production", "app.env", "app.secret", ".secrets.env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "config.json", "hosts.yml", "id_rsa", "id_ed25519"} {
				if matched, _ := path.Match(path.Base(v), candidate); matched && a.protected(path.Join(path.Dir(v), candidate), cwd) {
					expanded = append(expanded, path.Join(path.Dir(v), candidate))
				}
			}
			matches, err := filepath.Glob(a.resolve(v, cwd))
			if err != nil || a.globs+len(matches) > 200 {
				a.uncertain = true
				return nil, false
			}
			a.globs += len(matches)
			if len(matches) > 0 {
				expanded = append(expanded, matches...)
				continue
			}
		}
		expanded = append(expanded, v)
	}
	return expanded, true
}

// CheckBudget exercises the parser boundary without relying on shell execution.
func CheckBudget(source string) error {
	if len(source) > 40<<10 {
		return ErrIndeterminate
	}
	return nil
}
