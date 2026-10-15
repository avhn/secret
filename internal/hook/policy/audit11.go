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
		value := strings.TrimLeft(match[1], "><")
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
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	call, name := a.stdinCall(call, cwd)
	name = strings.ToLower(name)
	if !optionIn("cat tee", name) {
		return false
	}
	writesData := a.messageSubst
	for _, target := range stmt.Redirs {
		if strings.Contains(target.Op.String(), ">") && target.Word != nil {
			// Here-strings supply stdin; they are not output destinations.
			if target.Op.String() == "<<<" {
				continue
			}
			values, known := a.expandWord(target.Word, cwd)
			if !known || len(values) != 1 || a.inputProtected(values[0], cwd) {
				return false
			}
			writesData = true
		}
	}
	if name == "tee" {
		options := true
		for _, word := range call.Args[1:] {
			values, known := a.expandWord(word, cwd)
			if !known {
				return false
			}
			for _, value := range values {
				if options && value == "--" {
					options = false
					continue
				}
				if options && strings.HasPrefix(value, "-") {
					continue
				}
				if a.inputProtected(value, cwd) {
					return false
				}
				writesData = true
			}
		}
	}
	return writesData
}

func inertMessagePipe(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 1 || literal(call.Args[0]) != "cat" || len(stmt.Redirs) != 1 {
		return false
	}
	r := stmt.Redirs[0]
	return (r.Op.String() == "<<" || r.Op.String() == "<<-") && r.Hdoc != nil && inertHeredoc(r)
}

// Quoted heredocs have literal AST bodies. Unquoted substitutions must be
// walked normally, even when stdout becomes a commit or pull-request body.
func inertHeredoc(redir *syntax.Redirect) bool {
	inert := true
	syntax.Walk(redir.Hdoc, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ParamExp, *syntax.ArithmExp:
			inert = false
		}
		return inert
	})
	return inert
}

// Message-file stdin from an inert heredoc is data, not executable code.
func inertMessageStdin(stmt *syntax.Stmt) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	call = unwrapCall(call)
	if len(call.Args) < 3 {
		return false
	}
	for _, redir := range stmt.Redirs {
		if redir.Hdoc != nil && !inertHeredoc(redir) {
			return false
		}
	}
	name := literal(call.Args[0])
	if name != "git" && name != "gh" {
		return false
	}
	args := make([]string, 0, len(call.Args)-1)
	for _, word := range call.Args[1:] {
		args = append(args, literal(word))
	}
	if name == "git" && !optionIn("commit tag", args[0]) {
		return false
	}
	if name == "gh" && !optionIn("pr issue", args[0]) {
		return false
	}
	for i, v := range args {
		if name == "git" && (v == "-F" || v == "--file") && i+1 < len(args) && args[i+1] == "-" || name == "gh" && v == "--body-file" && i+1 < len(args) && args[i+1] == "-" || v == "--file=-" || v == "--body-file=-" || v == "-F-" {
			return true
		}
	}
	return false
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
var protectedLiteralToken = regexp.MustCompile(`(?i)(?:\.vault-token|\.pgpass|application_default_credentials\.json|\.kube/config|\.terraform\.d/credentials\.tfrc\.json|\.cargo/credentials(?:\.toml)?|\.config/gcloud/(?:credentials\.db|access_tokens\.db|legacy_credentials/)|\.env(?:\.[a-z0-9_-]+)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.gitconfig|\.gitmodules|(?:^|/)\.git/|git/config|\.ssh/id_[a-z0-9_-]+|\.aws/credentials|\.docker/config\.json|\.config/gh/hosts\.yml|[a-z0-9_.-]+\.secret(?:[^a-z0-9_-]|$))`)

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
		if i > 0 && (literal(args[i-1]) == "-m" || literal(args[i-1]) == "--message" || strings.HasPrefix(literal(args[i-1]), "-") && !strings.HasPrefix(literal(args[i-1]), "--") && strings.HasSuffix(literal(args[i-1]), "m")) {
			return true
		}
		value := literal(args[i])
		if strings.HasPrefix(value, "--message=") {
			return true
		}
		if strings.HasPrefix(value, "-") && !strings.HasPrefix(value, "--") && strings.Contains(value, "m") && !strings.ContainsAny(value, " =") {
			return true
		}
		return false
	}
	if name == "gh" {
		if i > 0 && (literal(args[i-1]) == "--title" || literal(args[i-1]) == "--body") {
			return true
		}
		return strings.HasPrefix(literal(args[i]), "--title=") || strings.HasPrefix(literal(args[i]), "--body=")
	}
	return false
}
