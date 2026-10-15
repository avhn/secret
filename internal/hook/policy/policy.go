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

	"github.com/avhn/secret/internal/hook/patch"
	"github.com/avhn/secret/internal/hook/roles"
	"github.com/avhn/secret/internal/hook/search"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

var ErrIndeterminate = errors.New("indeterminate shell command")

// Analyze returns a fixed denial reason, or an empty reason for an allowed
// command. Unsupported content-producing syntax is not treated as safe.
func Analyze(source, cwd, home string, protected func(string, string) bool) string {
	if !filepath.IsAbs(cwd) {
		return roles.Indeterminate
	}
	if invalidControls(source) {
		return roles.Indeterminate
	}
	// A deeply nested literal -c chain can hide shell code behind repeated
	// shell-quote boundaries. Never let it outlive the recursion budget.
	if strings.Count(source, "bash -c")+strings.Count(source, "sh -c") > 4 && (witness(source) || riskyRole(source)) {
		return roles.Indeterminate
	}
	a := &analyzer{protected: protected, cwd: cwd, home: home, deadline: time.Now().Add(2 * time.Second), configUntrusted: strings.Contains(source, "RIPGREP_CONFIG_PATH"), source: source}
	a.fragment(source, 0)
	if a.reason != "" {
		return a.reason
	}
	if a.structuralUncertain || a.uncertain && (witness(source) || riskyRole(source) || contentSyntax(source)) {
		return roles.Indeterminate
	}
	return ""
}

// AnalyzeArgv checks already-tokenized host arguments without joining them
// into shell source. Only explicit bash/sh -c source is parsed as shell code.
func AnalyzeArgv(argv []string, cwd, home string, protected func(string, string) bool) string {
	if !filepath.IsAbs(cwd) || len(argv) == 0 || len(argv) > 256 {
		return roles.Indeterminate
	}
	for _, arg := range argv {
		if len(arg) > 40<<10 || invalidControls(arg) {
			return roles.Indeterminate
		}
	}
	a := &analyzer{protected: protected, cwd: cwd, home: home, deadline: time.Now().Add(2 * time.Second), configUntrusted: strings.Contains(strings.Join(argv, " "), "RIPGREP_CONFIG_PATH")}
	a.command(argv, 0, cwd, false)
	if a.reason != "" {
		return a.reason
	}
	if a.structuralUncertain || a.uncertain && (witness(strings.Join(argv, " ")) || riskyRole(strings.Join(argv, " ")) || contentSyntax(strings.Join(argv, " "))) {
		return roles.Indeterminate
	}
	return ""
}

type analyzer struct {
	protected           func(string, string) bool
	cwd, home, reason   string
	words, globs        int
	uncertain           bool
	inRun               bool
	configUntrusted     bool
	structuralUncertain bool
	env                 map[string]string
	gitRoots            []string
	source              string
	assignments         map[string]int
	loopVars            map[string]string
	messageSubst        bool
	heredoc             map[*syntax.Word]string
	cdpath              bool
	indirect            bool
	deadline            time.Time
}

func witness(source string) bool {
	s := strings.ToLower(strings.ReplaceAll(source, `\`, ""))
	for _, v := range []string{".env", ".secret", ".secrets", ".netrc", ".npmrc", ".pypirc", ".aws/credentials", ".docker/config.json", ".config/gh/hosts.yml", ".git-credentials", ".ssh/id_", "/environ", "secret-tool", "printenv", "gh auth token", "$token", "$password", "$secret"} {
		if strings.Contains(s, v) {
			return true
		}
	}
	for _, phrase := range []string{"security find-", "git credential fill", "secret get", "secret exec", "pbpaste", "wl-paste", "rg ", "git grep", "env ", "gh auth token", "gcloud auth print-", "aws configure get aws_", "aws configure export-credentials", "op read", "op item get", "pass show", "secret-tool lookup", "kwallet-query -r", "ps e", "jq -n env"} {
		if strings.Contains(s, phrase) {
			return true
		}
	}
	return strings.Contains(s, ".en*") || strings.Contains(s, ".en{") || strings.Contains(s, ".{env")
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

// fragmentAt preserves the caller's scoped working directory for nested code.
func (a *analyzer) fragmentAt(source string, depth int, cwd string) {
	old := a.cwd
	a.cwd = cwd
	a.fragment(source, depth)
	a.cwd = old
}

// commandName identifies a literal command without evaluating its words.
func commandName(stmt *syntax.Stmt) string {
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
		return path.Base(literal(call.Args[0]))
	}
	return ""
}

func (a *analyzer) fragment(source string, depth int) {
	if invalidControls(source) {
		a.reason = roles.Indeterminate
		return
	}
	if a.reason != "" {
		return
	}
	if len(source) > 8192 && (len(source) > 1<<20 || !strings.Contains(source, "<<")) || depth > 4 || time.Now().After(a.deadline) {
		a.structuralUncertain = true
		a.uncertain = true
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		a.uncertain = true
		// Unparseable source has no classified operands to exempt from P18.
		// Bash and the parser can disagree on arithmetic-looking command
		// substitutions. Never certify opaque substitution-bearing source.
		if hasProtectedLiteral(source) || gitToken.MatchString(source) || strings.Contains(source, "$(") || strings.Contains(source, "`") {
			a.reason = roles.Indeterminate
		}
		return
	}
	if len(source) > 8192 {
		payload := 0
		if a.heredoc == nil {
			a.heredoc = make(map[*syntax.Word]string)
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			if redir, ok := node.(*syntax.Redirect); ok && redir.Hdoc != nil {
				body := a.raw(redir.Hdoc)
				a.heredoc[redir.Hdoc] = body
				payload += len(body)
			}
			return true
		})
		if len(source)-payload > 8192 {
			a.structuralUncertain = true
			a.reason = roles.Indeterminate
			return
		}
	}
	a.stmts(file.Stmts, depth, a.cwd)
}
func (a *analyzer) stmts(stmts []*syntax.Stmt, depth int, cwd string) string {
	if depth > 4 || time.Now().After(a.deadline) {
		a.structuralUncertain = true
		a.uncertain = true
		return cwd
	}
	for _, s := range stmts {
		if a.reason != "" {
			break
		}
		if call, ok := s.Cmd.(*syntax.CallExpr); ok && len(s.Redirs) > 0 {
			for _, assign := range call.Assigns {
				if assign.Name != nil && !assign.Append && optionIn("GIT_CONFIG_GLOBAL XDG_CONFIG_HOME HOME GIT_DIR GIT_COMMON_DIR", assign.Name.Value) {
					if a.env == nil {
						a.env = make(map[string]string)
					}
					a.env[assign.Name.Value] = literal(assign.Value)
				}
			}
		}
		for _, r := range s.Redirs {
			if r.Hdoc != nil {
				body := a.raw(r.Hdoc)
				if (hasProtectedLiteral(body) || gitToken.MatchString(body)) && !a.inertCatTeeBody(s, cwd) {
					a.reason = roles.FileInput
				}
			}
			if r.Op.String() == "<<<" && (hasProtectedLiteral(a.raw(r.Word)) || gitToken.MatchString(a.raw(r.Word))) && !a.inertCatTeeBody(s, cwd) {
				a.reason = roles.FileInput
			}
			a.walkWord(r.Word, depth, cwd)
			a.walkWord(r.Hdoc, depth, cwd)
			op := r.Op.String()
			if strings.Contains(op, ">") || op == "<>" {
				if r.Word == nil || len(r.Word.Parts) == 0 {
					a.reason = roles.Indeterminate
				} else if targets, ok := a.expandWord(r.Word, cwd); !ok || len(targets) != 1 {
					a.reason = roles.Indeterminate
				} else if gitToken.MatchString(targets[0]) || a.writeProtected(targets[0], cwd) || a.uncertainWriteWord(r.Word, cwd) {
					a.reason = roles.FileInput
				}
			}
			if op == "<" || op == "<>" || op == "<&" {
				if a.protectedWord(r.Word, cwd) {
					a.reason = "input redirect reads a protected store"
				}
			}
		}
		switch cmd := s.Cmd.(type) {
		case *syntax.CallExpr:
			cmd = unwrapCall(cmd)
			if a.shellStdinCall(cmd, cwd) || launcherStdin(cmd, s.Redirs) {
				a.reason = roles.Indeterminate
				for _, r := range s.Redirs {
					switch r.Op.String() {
					case "<<<":
						if body := literal(r.Word); body != "" {
							a.shellValue(body, depth, cwd)
						} else {
							a.reason = roles.Indeterminate
						}
					case "<<", "<<-":
						if delim := a.raw(r.Word); (strings.HasPrefix(delim, "'") || strings.HasPrefix(delim, "\"")) && r.Hdoc != nil {
							a.shellValue(literal(r.Hdoc), depth, cwd)
						} else {
							a.reason = roles.Indeterminate
						}
					case "<", "<>", "<&":
						a.reason = roles.Indeterminate
					}
				}
			}
			if a.reason != "" {
				break
			}
			for _, assign := range cmd.Assigns {
				if assign.Name != nil {
					if assign.Name.Value == "CDPATH" {
						a.cdpath = true
						cwd = ""
					}
					if assign.Append {
						a.hookAppend(assign.Name.Value, literal(assign.Value), depth, cwd)
					} else {
						a.hookAssignment(assign.Name.Value, literal(assign.Value), depth, cwd)
					}
				}
			}
			if len(cmd.Args) > 0 && path.Base(literal(cmd.Args[0])) == "apply_patch" {
				found := false
				for _, r := range s.Redirs {
					if r.Hdoc != nil {
						found = true
						if reason := patch.Decision(a.raw(r.Hdoc), cwd, "", a.home); reason != "" {
							a.reason = reason
						}
					}
				}
				if !found {
					a.reason = roles.Indeterminate
				}
			}
			if len(cmd.Args) == 0 {
				for _, assign := range cmd.Assigns {
					if assign.Name != nil && !assign.Append && literal(assign.Value) != "" {
						if a.assignments == nil {
							a.assignments = make(map[string]int)
						}
						a.assignments[assign.Name.Value]++
					}
				}
				for _, assign := range cmd.Assigns {
					a.walkWord(assign.Value, depth, cwd)
				}
				continue
			}
			for _, assign := range cmd.Assigns {
				a.walkWord(assign.Value, depth, cwd)
			}
			if len(cmd.Args) > 1 && path.Base(literal(cmd.Args[0])) == "secret" && literal(cmd.Args[1]) == "run" {
				for i, w := range cmd.Args {
					if literal(w) == "--" && i+1 < len(cmd.Args) {
						old := a.inRun
						a.inRun = true
						a.fragmentAt(a.rawArgs(cmd.Args[i+1:]), depth+1, cwd)
						a.inRun = old
						break
					}
					a.walkWord(w, depth, cwd)
				}
				continue
			}
			priorUncertain := a.uncertain
			message := len(cmd.Args) > 1 && (strings.EqualFold(literal(cmd.Args[0]), "git") && (literal(cmd.Args[1]) == "commit" || literal(cmd.Args[1]) == "tag") || strings.EqualFold(literal(cmd.Args[0]), "gh") && len(cmd.Args) > 2 && (literal(cmd.Args[1]) == "pr" || literal(cmd.Args[1]) == "issue"))
			priorMessage := a.messageSubst
			a.messageSubst = message
			nestedUncertain := false
			words := make([]string, 0, len(cmd.Args))
			unknown := false
			for idx, w := range cmd.Args {
				// A filtered child may use a credential in a curl header, not a file.
				if a.inRun && path.Base(literal(cmd.Args[0])) == "curl" && idx > 0 && literal(cmd.Args[idx-1]) == "-H" {
					a.walkWord(w, depth, cwd)
					words = append(words, "header")
					continue
				}
				if literal(cmd.Args[0]) == "jq" && a.raw(w) == `"$ENV"` {
					words = append(words, "$ENV")
					continue
				}
				if idx == 0 && (w.Lit() == "[" || literal(w) == "[") {
					words = append(words, "[")
					continue
				}
				a.walkWord(w, depth, cwd)
				nestedUncertain = nestedUncertain || a.uncertain
				values, ok := a.expandWord(w, cwd)
				if !ok {
					unknown = true
					words = append(words, "")
					continue
				}
				words = append(words, values...)
			}
			a.messageSubst = priorMessage
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
			name := strings.ToLower(path.Base(words[0]))
			for i, w := range cmd.Args[1:] {
				if unmodelledCommand(name) && hasProtectedLiteral(a.raw(w)) && !messageOperand(name, cmd.Args, i+1) {
					a.reason = roles.FileInput
					break
				}
			}
			if a.reason != "" {
				break
			}
			args := words[1:]
			if writePatternCommand(name, cmd.Args) {
				a.reason = roles.Indeterminate
				break
			}
			if shellPathOptions(name, args) {
				cwd = ""
				a.cdpath = true
			}
			a.recordIndirect(name, args, unknown)
			if name == "cd" || name == "pushd" || name == "popd" || name == "dirs" {
				for len(args) > 0 && len(args[0]) > 1 && strings.HasPrefix(args[0], "-") {
					option := args[0]
					args = args[1:]
					if option == "--" {
						break
					}
					if strings.Trim(option[1:], "LPe@") != "" {
						unknown = true
					}
				}
				if len(args) == 1 && args[0] != "-" && !unknown && !a.cdpath && cwd != "" && name == "cd" && !strings.HasPrefix(args[0], "~") {
					cwd = a.resolve(args[0], cwd)
				} else {
					cwd = ""
					a.uncertain = true
				}
				continue
			}
			if (name == "source" || name == ".") && len(args) > 0 && (args[0] == "/dev/stdin" || strings.HasPrefix(args[0], "/dev/fd/") || strings.HasPrefix(args[0], "/proc/") && strings.Contains(args[0], "/fd/")) {
				a.reason = roles.Indeterminate
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
					if witness(code) || a.inlineGitDir(code, cwd) || strings.Contains(code, "ENV") || strings.Contains(strings.ToLower(code), "getenv") || strings.Contains(code, ".environ") || strings.Contains(code, "process.env") {
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
			if (name == "echo" || name == "printf") && a.words <= 256 && time.Now().Before(a.deadline) {
				a.uncertain = priorUncertain || nestedUncertain || a.structuralUncertain
			}
			if name == "kill" && unknown && safePIDLookup(cmd.Args) && a.reason == "" {
				a.uncertain = priorUncertain
			}
			if unknown && name == "make" && strings.Contains(a.rawArgs(cmd.Args), "-f") && a.reason == "" {
				a.reason = roles.Indeterminate
			}
			if unknown && roles.Reading(name) && a.reason == "" && !(name == "kill" && safePIDLookup(cmd.Args)) {
				a.reason = roles.Indeterminate
			}
		case *syntax.BinaryCmd:
			if (cmd.Op.String() == "|" || cmd.Op.String() == "|&") && (a.shellStdinStatement(cmd.Y, cwd) || launcherStdinStatement(cmd.Y)) {
				a.reason = roles.Indeterminate
				break
			}
			if a.inRun && cmd.Op.String() == "|" && commandName(cmd.X) == "printf" && commandName(cmd.Y) == "curl" && !stdoutRedirect(cmd.X) {
				a.printerPipe(cmd.X, depth, cwd)
				a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
				break
			}
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
				if cmd.Op.String() == "&&" || cmd.Op.String() == "||" {
					if cmd.Op.String() == "||" {
						leftCWD = joinedCWD(cwd, leftCWD)
					}
					cwd = joinedCWD(cwd, a.stmts([]*syntax.Stmt{cmd.Y}, depth, leftCWD))
				} else {
					a.stmts([]*syntax.Stmt{cmd.Y}, depth, cwd)
				}
			}
		case *syntax.Subshell:
			a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.Block:
			cwd = a.stmts(cmd.Stmts, depth, cwd)
		case *syntax.FuncDecl:
			cwd = joinedCWD(cwd, a.stmts([]*syntax.Stmt{cmd.Body}, depth, cwd))
		case *syntax.IfClause:
			for clause := cmd; clause != nil; clause = clause.Else {
				cwd = joinedCWD(cwd, a.stmts(clause.Cond, depth, cwd))
				cwd = joinedCWD(cwd, a.stmts(clause.Then, depth, cwd))
			}
		case *syntax.WhileClause:
			cwd = joinedCWD(cwd, a.stmts(cmd.Cond, depth, cwd))
			cwd = joinedCWD(cwd, a.stmts(cmd.Do, depth, cwd))
		case *syntax.ForClause:
			a.walkNode(cmd.Loop, depth, cwd)
			if loop, ok := cmd.Loop.(*syntax.WordIter); ok {
				for _, w := range loop.Items {
					a.walkWord(w, depth, cwd)
				}
				if loop.Name != nil && len(loop.Items) > 0 {
					safe := true
					for _, w := range loop.Items {
						if literal(w) == "" || a.inputProtected(literal(w), cwd) {
							safe = false
						}
					}
					if safe {
						if a.loopVars == nil {
							a.loopVars = make(map[string]string)
						}
						a.loopVars[loop.Name.Value] = literal(loop.Items[0])
					}
				}
			}
			cwd = joinedCWD(cwd, a.stmts(cmd.Do, depth, cwd))
			if loop, ok := cmd.Loop.(*syntax.WordIter); ok && loop.Name != nil {
				delete(a.loopVars, loop.Name.Value)
			}
		case *syntax.CaseClause:
			a.walkWord(cmd.Word, depth, cwd)
			for _, item := range cmd.Items {
				for _, pattern := range item.Patterns {
					a.walkWord(pattern, depth, cwd)
				}
				cwd = joinedCWD(cwd, a.stmts(item.Stmts, depth, cwd))
			}
			a.uncertain = true
		case *syntax.DeclClause:
			a.walkNode(cmd, depth, cwd)
			args := make([]string, 0, len(cmd.Args))
			for _, assign := range cmd.Args {
				if assign.Name != nil {
					if assign.Name.Value == "CDPATH" {
						a.cdpath = true
						cwd = ""
					}
					if assign.Append {
						a.hookAppend(assign.Name.Value, literal(assign.Value), depth, cwd)
					} else {
						a.hookAssignment(assign.Name.Value, literal(assign.Value), depth, cwd)
					}
				}
				if assign.Name != nil {
					if assign.Value != nil {

						args = append(args, assign.Name.Value+"="+literal(assign.Value))
					} else {
						args = append(args, assign.Name.Value)
					}
				} else if assign.Value != nil {
					values, ok := a.expandWord(assign.Value, cwd)
					if !ok {
						a.indirect = true
					} else {
						args = append(args, values...)
					}
				}
			}
			a.recordIndirect(cmd.Variant.Value, args, false)
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
		case *syntax.TimeClause:
			if cmd.Stmt != nil {
				cwd = a.stmts([]*syntax.Stmt{cmd.Stmt}, depth, cwd)
			}
		case *syntax.CoprocClause:
			a.walkWord(cmd.Name, depth, cwd)
			if cmd.Stmt == nil {
				a.reason = roles.Indeterminate
			} else {
				// In `coproc sh < file`, the parser stores sh as Name and
				// leaves the redirected statement without a command.
				if cmd.Name != nil && cmd.Stmt.Cmd == nil && shellName(literal(cmd.Name)) {
					a.command([]string{literal(cmd.Name)}, depth+1, cwd, false)
				}
				if a.reason == "" {
					a.stmts([]*syntax.Stmt{cmd.Stmt}, depth, cwd)
				}
			}
		case *syntax.LetClause, *syntax.ArithmCmd:
			a.walkNode(cmd, depth, cwd)
			a.uncertain = true
		default:
			a.walkNode(cmd, depth, cwd)
			a.uncertain = true
		}
	}
	return cwd
}

var pidLookup = regexp.MustCompile(`^\$\(pgrep [a-zA-Z0-9_.-]+\)$`)

// PID selection is not a content-producing file lookup or a write target.
func safePIDLookup(words []*syntax.Word) bool {
	found := false
	for _, w := range words {
		raw := literal(w)
		if raw != "" {
			continue
		}
		var b strings.Builder
		syntax.NewPrinter().Print(&b, w)
		if !pidLookup.MatchString(b.String()) {
			return false
		}
		found = true
	}
	return found
}

func implicitListing(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	return ok && len(call.Args) == 1
}

// xargsListing checks only an AST-connected stdout pipe into a reader.
// It never relies on the printed output of an upstream command.
func (a *analyzer) xargsListing(upstream, downstream *syntax.Stmt, cwd string) bool {
	call, ok := downstream.Cmd.(*syntax.CallExpr)
	if ok {
		call = unwrapCall(call)
	}
	if !ok || len(call.Args) < 2 || literal(call.Args[0]) != "xargs" {
		return false
	}
	// An implicit cwd listing supplies names to xargs even for echo.
	if commandName(upstream) == "ls" && implicitListing(upstream) && literal(call.Args[len(call.Args)-1]) != "ls" && a.treeProtected(".", cwd) {
		return true
	}
	reader := false
	for _, w := range call.Args[1:] {
		if roles.Reading(path.Base(literal(w))) && literal(w) != "" {
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
		if literal(w) == "" {
			return false
		}
		words = append(words, literal(w))
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
	for _, r := range s.Redirs {
		a.walkWord(r.Word, depth, cwd)
		a.walkWord(r.Hdoc, depth, cwd)
		if strings.HasPrefix(r.Op.String(), "<") && a.protectedWord(r.Word, cwd) {
			a.reason = "input redirect reads a protected store"
		}
	}
	call, ok := s.Cmd.(*syntax.CallExpr)
	if !ok {
		a.stmts([]*syntax.Stmt{s}, depth, cwd)
		return
	}
	for _, assign := range call.Assigns {
		if assign.Name != nil {
			if assign.Name.Value == "CDPATH" {
				a.cdpath = true
				cwd = ""
			}
			if assign.Append {
				a.hookAppend(assign.Name.Value, literal(assign.Value), depth, cwd)
			} else {
				a.hookAssignment(assign.Name.Value, literal(assign.Value), depth, cwd)
			}
		}
		a.walkNode(assign, depth, cwd)
	}
	words := make([]string, 0, len(call.Args))
	for _, w := range call.Args {
		if literal(call.Args[0]) == "jq" && a.raw(w) == `"$ENV"` {
			words = append(words, "$ENV")
			continue
		}
		a.walkWord(w, depth, cwd)
		prior := a.uncertain
		v, ok := a.expandWord(w, cwd)
		if !ok {
			if a.inRun && literal(call.Args[0]) == "printf" && roles.CredentialExpansion(a.raw(w)) {
				a.uncertain = prior
				words = append(words, "filtered credential")
				continue
			}
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
	if depth > 4 || time.Now().After(a.deadline) {
		a.reason = roles.Indeterminate
		return
	}
	if len(words) == 0 || a.reason != "" {
		return
	}
	if strings.Contains(words[0], "/") && a.inputProtected(words[0], cwd) {
		a.reason = roles.FileInput
		return
	}
	name := strings.ToLower(path.Base(words[0]))
	args := words[1:]
	if unmodelledCommand(name) {
		for _, arg := range args {
			if hasProtectedLiteral(arg) {
				a.reason = roles.FileInput
				return
			}
		}
	}
	if p18InlineCode(name, args) {
		a.reason = roles.FileInput
		return
	}
	if name == "setsid" {
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			args = args[1:]
		}
		a.command(args, depth+1, cwd, direct)
		return
	}
	if name == "systemd-run" && launcherShellOption(args) {
		a.reason = roles.Indeterminate
		return
	}
	if name == "script" {
		for i, v := range args {
			if v == "-c" || v == "-qc" || v == "-cq" {
				if i+1 >= len(args) {
					a.reason = roles.Indeterminate
					return
				}
				a.shellValue(args[i+1], depth, cwd)
				return
			}
		}
		a.reason = roles.Indeterminate
		return
	}
	dialect := name
	if shellName(name) {
		name = "sh"
	}
	if strings.HasPrefix(name, "git-") && strings.Contains(words[0], "/") && !strings.Contains(words[0], "/git-core/") {
		for _, operand := range args {
			if a.inputProtected(operand, cwd) {
				a.reason = roles.FileInput
				return
			}
		}
	}
	if strings.HasPrefix(name, "git-") && (!strings.Contains(words[0], "/") || strings.Contains(words[0], "/git-core/")) {
		if _, ok := a.env["PATH"]; ok {
			a.reason = roles.Indeterminate
			return
		}
		for _, v := range args {
			if a.inputProtected(v, cwd) {
				a.reason = roles.FileInput
				return
			}
		}
		if name == "git-" {
			a.reason = roles.Indeterminate
			return
		}
		args = append([]string{name[4:]}, args...)
		name = "git"
	}
	if name == "busybox" || name == "toybox" {
		if len(args) == 0 || strings.HasPrefix(args[0], "-") {
			a.reason = roles.Indeterminate
			return
		}
		a.command(args, depth+1, cwd, direct)
		return
	}
	if optionIn("doas run0 pkexec runuser expect machinectl", name) {
		if len(args) == 0 || name == "expect" && (args[0] == "-" || len(args) > 1 && args[0] == "-f" && (args[1] == "-" || args[1] == "/dev/stdin")) || name == "machinectl" && len(args) == 1 && args[0] == "shell" {
			a.reason = roles.Indeterminate
			return
		}
		if name == "machinectl" && args[0] == "shell" || name == "doas" && launcherShellOption(args) {
			a.reason = roles.Indeterminate
			return
		}
	}
	if name == "sudo" && len(args) == 0 {
		a.reason = roles.Indeterminate
		return
	}
	if name == "sudo" && launcherShellOption(args) {
		a.reason = roles.Indeterminate
		return
	}
	if name == "su" && !strings.Contains(" "+strings.Join(args, " ")+" ", " -c ") && !strings.Contains(" "+strings.Join(args, " ")+" ", " --command ") {
		a.reason = roles.Indeterminate
		return
	}
	if a.indirect && indirectConsumer(name) {
		a.reason = roles.Indeterminate
		return
	}
	if name == "git" {
		a.gitCommand(args, depth, cwd, direct)
		return
	}
	if name == "compgen" {
		for _, arg := range args {
			if arg == "-e" || arg == "-v" || arg == "-A" && len(args) > 1 && args[1] == "variable" {
				a.reason = roles.Printer
				return
			}
		}
	}
	if name == "find" {
		for _, arg := range args {
			if optionIn("-fprintf -fprint0 -fls", arg) {
				// Output primaries have a destination operand and are checked
				// by configArgument, not rejected when writing public files.
				continue
			}
		}
	}
	if a.commandSlot(name, args, depth, cwd) {
		return
	}
	if optionIn("npm npx make rsync op gh curl kubectl aws gcloud docker", name) && name != "docker" {
		genericArgs := args
		if name == "gh" {
			genericArgs = make([]string, 0, len(args))
			for i := 0; i < len(args); i++ {
				if optionIn("--title --body", args[i]) {
					i++
					continue
				}
				if strings.HasPrefix(args[i], "--title=") || strings.HasPrefix(args[i], "--body=") {
					continue
				}
				genericArgs = append(genericArgs, args[i])
			}
		}
		a.unknownExecution(genericArgs, depth, cwd)
		if a.reason != "" {
			return
		}
	}
	if a.configArgument(name, args, cwd) {
		return
	}
	if name == "patch" {
		output := false
		for i, arg := range args {
			if (arg == "-o" || arg == "--output") && i+1 < len(args) || strings.HasPrefix(arg, "-o") && len(arg) > 2 || strings.HasPrefix(arg, "--output=") && len(arg) > len("--output=") {
				output = true
			}
		}
		if !output {
			a.reason = roles.Indeterminate
			return
		}
	}
	if optionIn("tar bsdtar unzip cpio 7z 7za", name) {
		a.archiveCommand(name, args, depth, cwd)
		return
	}
	if name == "parallel" {
		a.parallelCommand(args, depth, cwd)
		return
	}
	if a.writeCommand(name, args, cwd) {
		return
	}
	if a.auditCommand(name, args, depth, cwd, direct) {
		return
	}
	if _, ok := utilityTable[name]; ok {
		child, dir, shell := a.utilityChild(name, args, cwd)
		if a.reason == "" && name == "xargs" && !xargsHasArgFile(args) && !(len(child) > 0 && strings.EqualFold(path.Base(child[0]), "echo")) && !a.metadataChild(child, depth+1, dir) && a.treeProtectedAll(".", dir) {
			a.reason = roles.FileInput
		}
		if a.reason == "" && name == "xargs" && xargsHasArgFile(args) && len(child) > 0 && roles.KnownReader(strings.ToLower(path.Base(child[0]))) {
			a.reason = roles.Indeterminate
			return
		}
		if name == "sudo" && dir != cwd && !shell {
			a.command(child, depth+1, cwd, direct)
		}
		if a.reason != "" {
			return
		}
		if shell && name == "sudo" {
			if len(child) == 0 {
				a.reason = roles.Indeterminate
			} else if len(child) == 1 {
				a.fragmentAt(child[0], depth+1, dir)
			} else {
				a.command(child, depth+1, dir, direct)
			}
		} else if shell && len(child) == 1 {
			a.fragmentAt(child[0], depth+1, dir)
		} else {
			a.command(child, depth+1, dir, direct)
		}
		return
	}
	if strings.HasPrefix(name, "python") || name == "perl" || name == "ruby" || name == "node" {
		for i := 0; i < len(args); i++ {
			code := args[i]
			if name == "node" && code == "--env-file" {
				i++
				continue
			}
			if name == "node" && strings.HasPrefix(code, "--env-file=") {
				continue
			}
			if witness(code) || a.inlineGitDir(code, cwd) || strings.Contains(code, "ENV") || strings.Contains(strings.ToLower(code), "getenv") || strings.Contains(code, ".environ") || strings.Contains(code, "process.env") {
				a.reason = "interpreter argument names a protected file or credential operation"
				return
			}
		}
	}
	if name == "secret" {
		if len(args) > 0 {
			switch args[0] {
			case "list", "show", "stash", "clip", "help", "--help", "-h":
				return
			case "run":
				for i, arg := range args {
					if arg == "--" && i+1 < len(args) {
						a.command(args[i+1:], depth+1, cwd, false)
						return
					}
				}
				return
			}
		}
		a.reason = "secret get/exec or unknown subcommand is not an agent transport"
		return
	}
	if name == "[" || name == "[[" {
		return
	}
	for _, arg := range args {
		if arg == "--unrecognised" && (witness(strings.Join(args, " ")) || strings.Contains(" "+strings.Join(args, " ")+" ", " env ")) {
			a.reason = roles.Indeterminate
			return
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
			if v == "-files0-from" && i+1 < len(args) && a.inputProtected(args[i+1], cwd) || strings.HasPrefix(v, "-files0-from=") && a.inputProtected(strings.TrimPrefix(v, "-files0-from="), cwd) {
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
				roots := []string{}
				for j := 0; j < len(args); j++ {
					root := args[j]
					if root == "-H" || root == "-L" || root == "-P" || root == "--" || strings.HasPrefix(root, "-O") {
						continue
					}
					if root == "-D" {
						j++
						continue
					}
					if strings.HasPrefix(root, "-") || root == "(" || root == "!" {
						break
					}
					roots = append(roots, root)
				}
				if len(roots) == 0 {
					roots = []string{"."}
				}
				if !a.metadataChild(child, depth+1, cwd) {
					for _, root := range roots {
						if a.treeProtectedAll(root, cwd) {
							a.reason = roles.FileInput
							return
						}
					}
				}
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
	case "sh", "eval":
		if name == "eval" {
			a.indirect = true
			a.shellValue(strings.Join(args, " "), depth, cwd)
			return
		}
		a.shellCommand(dialect, args, depth, cwd)
		return
	case "env", "command", "builtin":
		if name == "env" {
			// Split-string supplies child words, not an environment dump.
			if len(args) >= 2 && (args[0] == "-S" || args[0] == "--split-string") {
				if args[1] == "echo" {
					a.command(args[1:], depth+1, cwd, direct)
					return
				}
				code := "env " + splitEnv(args[1])
				for _, arg := range args[2:] {
					code += " " + strconv.Quote(arg)
				}
				a.fragmentAt(code, depth+1, cwd)
				return
			}
			if len(args) > 0 && (strings.HasPrefix(args[0], "--split-string=") || strings.HasPrefix(args[0], "-S") && len(args[0]) > 2) {
				code := strings.TrimPrefix(args[0], "--split-string=")
				if strings.HasPrefix(args[0], "-S") {
					code = args[0][2:]
				}
				a.fragmentAt("env "+splitEnv(code), depth+1, cwd)
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
			if key, value, ok := strings.Cut(v, "="); ok {
				if strings.HasSuffix(key, "+") {
					a.hookAppend(strings.TrimSuffix(key, "+"), value, depth, cwd)
				} else {
					a.hookAssignment(key, value, depth, cwd)
				}
				if key == "CDPATH" {
					a.cdpath = true
					cwd = ""
				}
			}
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
		if name == "dotenv" {
			a.dotenvChild(args, depth, cwd)
			return
		}
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
		// Docker's printer rules do not certify arbitrary command options.
		// Its exec subcommand is not the shell builtin of the same name.
		dockerArgs := args
		if len(args) > 0 && args[0] == "exec" {
			dockerArgs = args[1:]
		} else if len(args) > 1 && args[0] == "compose" && args[1] == "exec" {
			dockerArgs = append([]string{"compose"}, args[2:]...)
		}
		a.unknownExecution(dockerArgs, depth, cwd)
		return
	}
	if !modelledCommand(name) && !shellName(name) && !optionIn("npm npx make rsync op gh curl kubectl aws gcloud", name) {
		a.unknownExecution(args, depth, cwd)
		if a.reason != "" {
			return
		}
	}
	if name == "rg" {
		// Nested wrappers cannot inherit the hook's rg config certification.
		a.reason = search.Scope(words, cwd, a.home, os.Getenv("RIPGREP_CONFIG_PATH"), a.configUntrusted || depth > 0 || cwd != a.cwd && os.Getenv("RIPGREP_CONFIG_PATH") != "" && !path.IsAbs(os.Getenv("RIPGREP_CONFIG_PATH")) || strings.Contains(strings.Join(words, " "), "RIPGREP_CONFIG_PATH"))
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
	operands := args
	if name == "gh" {
		// Titles and bodies are data, not file input operands. Keep every
		// other gh argument subject to the existing role checks.
		operands = make([]string, 0, len(args))
		for i := 0; i < len(args); i++ {
			if optionIn("--title --body", args[i]) {
				i++
				continue
			}
			if strings.HasPrefix(args[i], "--title=") || strings.HasPrefix(args[i], "--body=") {
				continue
			}
			operands = append(operands, args[i])
		}
	}
	if reason := roles.OperandReason(name, operands, func(path string) bool { return a.inputProtected(path, cwd) }); reason != "" {
		a.reason = reason
	}
}
func (a *analyzer) resolve(name, cwd string) string {
	if cwd == "" && !path.IsAbs(name) {
		return ""
	}
	if strings.HasPrefix(name, "~/") {
		name = a.home + "/" + name[2:]
	}
	if path.IsAbs(name) {
		return name
	}
	return cwd + "/" + name
}

func (a *analyzer) protectedWord(w *syntax.Word, cwd string) bool {
	values, ok := a.expandWord(w, cwd)
	if !ok {
		a.uncertain = true
		return true
	}
	for _, v := range values {
		if a.inputProtected(v, cwd) {
			return true
		}
	}
	return false
}
func (a *analyzer) raw(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	if body, ok := a.heredoc[w]; ok {
		return body
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
	a.walkNode(w, depth, cwd)
}

// walkNode visits substitutions in every supported expression shape without
// interpreting the expression or using its output as a filename.
func (a *analyzer) walkNode(node syntax.Node, depth int, cwd string) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(node syntax.Node) bool {
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
	if a.words > 256 || time.Now().After(a.deadline) {
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
	copy := *w
	syntax.SplitBraces(&copy)
	// Never pass SplitBraces results to syntax.Walk: this parser version
	// panics on BraceExp nodes, which are introduced by SplitBraces itself.
	values, ok := a.literalWord(&copy, cwd)
	if ok && len(values) > 1 {
		// Unquoted empty brace alternatives do not create empty argv entries.
		quoted := false
		syntax.Walk(w, func(n syntax.Node) bool {
			switch n.(type) {
			case *syntax.SglQuoted, *syntax.DblQuoted:
				quoted = true
			}
			return true
		})
		if quoted {
			// Mixed quoted/unquoted empty alternatives need field provenance.
			// Do not let a retained empty field shift a printer's subcommand.
			for _, value := range values {
				if value == "" {
					a.uncertain = true
				}
			}
		}
		if !quoted {
			nonempty := values[:0]
			for _, value := range values {
				if value != "" {
					nonempty = append(nonempty, value)
				}
			}
			values = nonempty
		}
	}
	return values, ok
}
func (a *analyzer) literalWord(w *syntax.Word, cwd string) ([]string, bool) {
	result := []string{""}
	patterns := []string{""}
	unquotedGlob := false
	for _, part := range w.Parts {
		var piece string
		var globPiece string
		switch n := part.(type) {
		case *syntax.Lit:
			piece = strings.ReplaceAll(n.Value, `\`, ``)
			if strings.Contains(n.Value, "{") && !strings.Contains(n.Value, `\{`) && (strings.Contains(piece, ",") || strings.Contains(piece, "..")) {
				a.uncertain = true
				return nil, false
			}
			globPiece = n.Value
			unquotedGlob = unquotedGlob || unescapedGlob(n.Value)
		case *syntax.SglQuoted:
			piece = n.Value
			if n.Dollar {
				var err error
				piece, err = strconv.Unquote("\"" + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(n.Value, `\'`, `'`), `\e`, `\x1b`), "\"", "\\\"") + "\"")
				if err != nil {
					a.uncertain = true
					return nil, false
				}
			}
		case *syntax.DblQuoted:
			for _, child := range n.Parts {
				switch x := child.(type) {
				case *syntax.Lit:
					piece += doubleLiteral(x.Value)
				case *syntax.CmdSubst:
					if !a.messageSubst || !inertCatHeredoc(x) {
						a.uncertain = true
						return nil, false
					}
					piece += "message"
				case *syntax.ParamExp:
					if x.Param == nil || x.Exp != nil || x.Repl != nil || x.Slice != nil || x.Index != nil || x.Length || x.Excl {
						a.uncertain = true
						return nil, false
					}
					if x.Param.Value == "PWD" && cwd != "" && !strings.Contains(a.source, "PWD=") {
						piece += cwd
					} else if value, ok := a.staticVariable(x.Param.Value); ok {
						piece += value
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
			if value, ok := a.loopVars[n.Param.Value]; ok {
				piece = value
			} else if value, ok := a.staticVariable(n.Param.Value); ok {
				piece = value
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
			nextPatterns := make([]string, 0, len(result)*len(n.Elems))
			for index, prefix := range result {
				for _, elem := range n.Elems {
					values, ok := a.literalWord(elem, cwd)
					if !ok {
						return nil, false
					}
					for _, v := range values {
						next = append(next, prefix+v)
						nextPatterns = append(nextPatterns, patterns[index]+escapeGlob(v))
						if len(next) > 64 {
							a.uncertain = true
							return nil, false
						}
					}
				}
			}
			result = next
			patterns = nextPatterns
			continue
		default:
			a.uncertain = true
			return nil, false
		}
		if globPiece == "" {
			globPiece = escapeGlob(piece)
		}
		for i := range result {
			result[i] += piece
			patterns[i] += globPiece
		}
	}
	expanded := make([]string, 0, len(result))
	for i, v := range result {
		pattern := patterns[i]
		if strings.HasPrefix(v, "~/") {
			v = a.home + "/" + v[2:]
			pattern = a.home + "/" + strings.TrimPrefix(pattern, "~/")
		}
		if unquotedGlob && strings.ContainsAny(v, "*?[") {
			for _, candidate := range []string{".env", ".env.production", "app.env", "app.secret", ".secrets.env", ".netrc", ".npmrc", ".pypirc", ".git-credentials", "credentials", "config.json", "hosts.yml", "id_rsa", "id_ed25519"} {
				if matched, _ := path.Match(path.Base(pattern), candidate); matched && a.inputProtected(path.Join(path.Dir(v), candidate), cwd) {
					expanded = append(expanded, path.Join(path.Dir(v), candidate))
				}
			}
			matches, valid := shellGlobMatches(pattern, cwd, a.deadline)
			if !valid || a.globs+len(matches) > 200 {
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

// literal decodes a strictly literal AST word with no ambient environment,
// substitutions, parameter expansion, filesystem access or shell execution.
func literal(word *syntax.Word) string {
	if word == nil {
		return ""
	}
	allowed := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case nil, *syntax.Word, *syntax.Lit, *syntax.SglQuoted, *syntax.DblQuoted:
		default:
			allowed = false
		}
		return true
	})
	if !allowed {
		return ""
	}
	// Reject active brace/glob/tilde syntax before Fields, even with its
	// filesystem callbacks disabled. Only quote removal is needed here.
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "{}*?[~") {
			return ""
		}
	}
	values, err := expand.Fields(&expand.Config{Env: expand.ListEnviron(), NoUnset: true}, word)
	if err != nil || len(values) != 1 {
		return ""
	}
	return values[0]
}

// unwrapCall preserves AST word provenance while stripping transparent command
// and builtin prefixes. It does not guess option arity for other wrappers.
func unwrapCall(call *syntax.CallExpr) *syntax.CallExpr {
	copy := *call
	for len(copy.Args) > 1 {
		name := literal(copy.Args[0])
		if name != "command" && name != "builtin" {
			break
		}
		i := 1
		if literal(copy.Args[i]) == "--" || name == "command" && literal(copy.Args[i]) == "-p" {
			i++
		}
		if i >= len(copy.Args) || strings.HasPrefix(literal(copy.Args[i]), "-") {
			break
		}
		copy.Args = copy.Args[i:]
	}
	return &copy
}

// doubleLiteral removes only escapes that Bash recognizes within double quotes.
func doubleLiteral(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) && strings.ContainsRune("\\\"$`\n", rune(value[i+1])) {
			i++
			if value[i] == '\n' {
				continue
			}
		}
		out.WriteByte(value[i])
	}
	return out.String()
}

// contentSyntax classifies uncertain fragments structurally, not by a narrow
// keyword list. Unknown executables and readers cannot certify safe output.
func contentSyntax(source string) bool {
	file, _ := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if file == nil {
		return false
	}
	risky := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			name := path.Base(literal(unwrapCall(call).Args[0]))
			switch name {
			case ":", "true", "false", "echo", "printf", "ls", "stat", "test", "[", "pwd", "cd", "basename", "dirname", "readlink", "realpath", "bash", "sh":
			default:
				risky = true
			}
		}
		return true
	})
	return risky
}
