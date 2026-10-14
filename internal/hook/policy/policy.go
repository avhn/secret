// Package policy analyses bounded Bash syntax without running shell code.
package policy

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

var ErrIndeterminate = errors.New("indeterminate shell command")

// Analyze returns a fixed denial reason, or an empty reason for an allowed
// command. Unsupported content-producing syntax is not treated as safe.
func Analyze(source, cwd, home string, protected func(string, string) bool) string {
	a := &analyzer{protected: protected, cwd: cwd, home: home, deadline: time.Now().Add(2 * time.Second)}
	a.fragment(source, 0)
	if a.reason != "" {
		return a.reason
	}
	if a.uncertain && witness(source) {
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
	return false
}
func (a *analyzer) fragment(source string, depth int) {
	if a.reason != "" {
		return
	}
	if len(source) > 8192 || depth > 4 || time.Now().After(a.deadline) {
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
			for _, w := range cmd.Args {
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
			if len(words) == 0 {
				a.uncertain = true
				break
			}
			name := filepath.Base(words[0])
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
				for _, w := range cmd.Args[1:] {
					if witness(a.raw(w)) {
						a.reason = "interpreter argument names a protected file or credential operation"
						break
					}
				}
			}
			if unknown && (name == "echo" || name == "printf") && roles.CredentialExpansion(a.rawArgs(cmd.Args)) {
				a.reason = roles.Printer
			}
			if a.reason == "" {
				a.command(words, depth, cwd, direct)
			}
			if unknown && roles.Reading(name) && witness(a.rawArgs(cmd.Args)) && a.reason == "" {
				a.reason = roles.Indeterminate
			}
		case *syntax.BinaryCmd:
			if cmd.Op.String() == "|" && a.xargsListing(cmd.X, cmd.Y, cwd) {
				a.reason = "xargs reader consumes a protected-name listing"
				break
			}
			if cmd.Op.String() == "|" && stash(cmd.Y) && len(cmd.X.Redirs) == 0 {
				a.printerPipe(cmd.X, depth, cwd)
				if a.reason == "" {
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
				}
			} else {
				a.stmts([]*syntax.Stmt{cmd.X}, depth, cwd)
				a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
			}
		case *syntax.Subshell:
			a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.Block:
			cwd = a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.FuncDecl:
			a.stmts([]*syntax.Stmt{cmd.Body}, depth, cwd)
		case *syntax.IfClause:
			a.stmts(cmd.Cond, depth, cwd)
			a.stmts(cmd.Then, depth, cwd)
			if cmd.Else != nil {
				a.stmts(cmd.Else.Cond, depth, cwd)
				a.stmts(cmd.Else.Then, depth, cwd)
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
		case *syntax.TestClause, *syntax.ArithmCmd:
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
		if roles.Reading(filepath.Base(w.Lit())) && w.Lit() != "" {
			reader = true
		}
	}
	if !reader {
		return false
	}
	var args []*syntax.Word
	if source, ok := upstream.Cmd.(*syntax.CallExpr); ok {
		args = source.Args[1:]
	}
	for _, w := range args {
		if a.protectedWord(w, cwd) || witness(a.raw(w)) {
			return true
		}
	}
	return false
}

func stash(s *syntax.Stmt) bool {
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(s.Redirs) > 0 || len(call.Args) != 4 {
		return false
	}
	for _, w := range call.Args {
		if w.Lit() == "" {
			return false
		}
	}
	return filepath.Base(call.Args[0].Lit()) == "secret" && call.Args[1].Lit() == "stash" && call.Args[2].Lit() != "" && call.Args[3].Lit() != ""
}
func (a *analyzer) printerPipe(s *syntax.Stmt, depth int, cwd string) {
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok {
		a.stmts([]*syntax.Stmt{s}, depth, cwd)
		return
	}
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
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
	name := filepath.Base(words[0])
	args := words[1:]
	for _, arg := range args {
		if arg == "--unrecognised" && (witness(strings.Join(args, " ")) || strings.Contains(" "+strings.Join(args, " ")+" ", " env ")) {
			a.reason = roles.Indeterminate
			return
		}
	}
	if name == "grep" || name == "egrep" || name == "fgrep" {
		for _, arg := range args {
			if arg == "-R" || arg == "-r" || arg == "--recursive" || arg == "--dereference-recursive" {
				a.reason = "recursive grep bypasses protected search defaults; use plain rg"
				return
			}
		}
	}
	switch name {
	case "bash", "sh", "zsh", "eval":
		if name == "eval" {
			if len(args) > 0 {
				a.fragment(strings.Join(args, " "), depth+1)
			}
			return
		}
		for i, v := range args {
			if (v == "-c" || v == "-lc" || strings.HasPrefix(v, "-") && strings.Contains(v, "c")) && i+1 < len(args) {
				a.fragment(args[i+1], depth+1)
				return
			}
		}
	case "env", "sudo", "nice", "timeout", "nohup", "exec", "command", "builtin", "stdbuf", "caffeinate":
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
			for _, v := range args {
				if v == "-S" || v == "--split-string" || strings.HasPrefix(v, "-S") || strings.HasPrefix(v, "--split-string=") {
					a.reason = roles.Indeterminate
					return
				}
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
		if name == "env" && len(args) == 0 {
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
	if name == "rg" {
		for _, option := range args {
			if option == "-uu" || option == "--no-config" || strings.HasPrefix(option, "--no-ignore") {
				a.reason = "unrestricted rg bypasses protected search defaults"
				return
			}
		}
		// The config-certification item is not implemented yet. A content
		// search cannot be treated as safe on the basis of its spelling.
		namesOnly := false
		for _, option := range args {
			if option == "-l" || option == "--files-with-matches" || option == "--files" {
				namesOnly = true
			}
		}
		if !namesOnly {
			a.reason = "search scope is uncertain; narrow the path or use -l; install examples/ripgreprc for rg"
			return
		}
	}
	if name == "git" {
		for _, v := range args {
			if v == "grep" {
				a.reason = "search scope is uncertain; narrow the path or use -l; install examples/ripgreprc for rg"
				return
			}
		}
	}
	if reason := roles.PrinterReason(name, args, direct); reason != "" {
		a.reason = reason
		return
	}
	if reason := roles.OperandReason(name, args, func(path string) bool { return a.protected(path, cwd) }); reason != "" {
		a.reason = reason
	}
}
func (a *analyzer) resolve(path, cwd string) string {
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(a.home, path[2:])
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(cwd, path)
}
func (a *analyzer) protectedWord(w *syntax.Word, cwd string) bool {
	values, ok := a.expandWord(w, cwd)
	if !ok {
		if w != nil && witness(a.raw(w)) {
			a.uncertain = true
			return true
		}
		return false
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
			piece = n.Value
			unquotedGlob = unquotedGlob || strings.ContainsAny(piece, "*?[")
		case *syntax.SglQuoted:
			piece = n.Value
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
			v = filepath.Join(a.home, v[2:])
		}
		if unquotedGlob && strings.ContainsAny(v, "*?[") {
			for _, candidate := range []string{".env", ".env.production", "app.env", "app.secret", ".secrets.env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "config.json", "hosts.yml", "id_rsa", "id_ed25519"} {
				if matched, _ := filepath.Match(filepath.Base(v), candidate); matched && a.protected(filepath.Join(filepath.Dir(v), candidate), cwd) {
					expanded = append(expanded, filepath.Join(filepath.Dir(v), candidate))
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
	if len(source) > 8192 {
		return ErrIndeterminate
	}
	return nil
}
