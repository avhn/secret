package policy

import (
	"mvdan.cc/sh/v3/syntax"
	"regexp"
	"strings"
)

// inlineGitDir inspects literal strings in inline interpreter code. It never
// evaluates the code or opens its referenced files.
var inlinePath = regexp.MustCompile(`['"]([^'"\r\n]+)['"]`)

func (a *analyzer) inlineGitDir(code, cwd string) bool {
	for _, match := range inlinePath.FindAllStringSubmatch(code, -1) {
		value := match[1]
		if strings.ContainsAny(value, " ;(){}") {
			continue
		}
		if a.configPath(value, cwd) {
			return true
		}
	}
	return false
}

// inertCatTeeBody certifies data-only stdin only when no output store is named.
func (a *analyzer) inertCatTeeBody(stmt *syntax.Stmt, cwd string) bool {
	name := strings.ToLower(commandName(stmt))
	if !optionIn("cat tee", name) {
		return false
	}
	writesData := a.messageSubst
	for _, target := range stmt.Redirs {
		if strings.Contains(target.Op.String(), ">") && target.Word != nil {
			if a.inputProtected(literal(target.Word), cwd) {
				return false
			}
			writesData = true
		}
	}
	if name == "tee" {
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			for _, word := range call.Args[1:] {
				value := literal(word)
				if !strings.HasPrefix(value, "-") {
					if a.inputProtected(value, cwd) {
						return false
					}
					writesData = true
				}
			}
		}
	}
	return writesData
}

func inertCatHeredoc(sub *syntax.CmdSubst) bool {
	if len(sub.Stmts) != 1 {
		return false
	}
	stmt := sub.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || literal(call.Args[0]) != "cat" || len(stmt.Redirs) != 1 {
		return false
	}
	redir := stmt.Redirs[0]
	return (redir.Op.String() == "<<" || redir.Op.String() == "<<-") && redir.Hdoc != nil
}

// protectedLiteralToken examines literal argv data after parsing. Dynamic
// operands are handled by the ordinary word and role checks.
var protectedLiteralToken = regexp.MustCompile(`(?i)(?:\.env(?:\.[a-z0-9_-]+)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.gitconfig|\.gitmodules|(?:^|/)\.git/|git/config|\.ssh/id_[a-z0-9_-]+|\.aws/credentials|\.docker/config\.json|\.config/gh/hosts\.yml|[a-z0-9_.-]+\.secret(?:[^a-z0-9_-]|$))`)

func hasProtectedLiteral(value string) bool {
	value = strings.ReplaceAll(strings.ReplaceAll(value, ".env.example", ""), ".env.template", "")
	return protectedLiteralToken.MatchString(value)
}

// p18InlineCode checks only executable interpreter option values. Script-file
// names and env-file options retain their existing input and data roles.
func p18InlineCode(name string, args []string) bool {
	if !interpreter(name) || name == "awk" || name == "gawk" || name == "jq" || name == "yq" {
		return false
	}
	for i, arg := range args {
		key, value, attached := strings.Cut(arg, "=")
		if (key == "--eval" || key == "--print") && (name == "node" || name == "nodejs") {
			if attached && hasProtectedLiteral(value) || !attached && i+1 < len(args) && hasProtectedLiteral(args[i+1]) {
				return true
			}
			continue
		}
		if len(arg) < 2 || arg[0] != '-' || !(arg[1] == 'c' && strings.HasPrefix(name, "python") || arg[1] == 'e' && (name == "perl" || name == "ruby" || name == "node" || name == "nodejs") || arg[1] == 'E' && name == "perl" || arg[1] == 'p' && (name == "node" || name == "nodejs") || arg[1] == 'r' && name == "php") {
			continue
		}
		if len(arg) > 2 && hasProtectedLiteral(arg[2:]) || len(arg) == 2 && i+1 < len(args) && hasProtectedLiteral(args[i+1]) {
			return true
		}
	}
	return false
}

func messageOperand(name string, args []*syntax.Word, i int) bool {
	if name == "git" && len(args) > 1 && (literal(args[1]) == "commit" || literal(args[1]) == "tag") {
		if i > 0 && (literal(args[i-1]) == "-m" || literal(args[i-1]) == "--message") {
			return true
		}
		return strings.HasPrefix(literal(args[i]), "--message=") || strings.HasPrefix(literal(args[i]), "-m")
	}
	if name == "gh" {
		if i > 0 && (literal(args[i-1]) == "--title" || literal(args[i-1]) == "--body") {
			return true
		}
		return strings.HasPrefix(literal(args[i]), "--title=") || strings.HasPrefix(literal(args[i]), "--body=")
	}
	return false
}
