package policy

import (
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// The parser accepts some AST shapes that Bash rejects. Certify these framing
// rules before walking commands, including inactive branches and substitutions.
func bashFraming(root syntax.Node) bool {
	valid := true
	syntax.Walk(root, func(node syntax.Node) bool {
		if !valid {
			return false
		}
		switch cmd := node.(type) {
		case *syntax.Redirect:
			// Document can finish a command substitution without consuming
			// its pending heredoc. A missing body is not valid inner framing.
			valid = (cmd.Op != syntax.Hdoc && cmd.Op != syntax.DashHdoc) || cmd.Hdoc != nil
		case *syntax.CallExpr:
			// The parser leaves these misplaced reserved words as literal calls.
			// Quoting, escaping and prefix assignments remove that keyword role.
			if len(cmd.Assigns) == 0 && len(cmd.Args) > 0 {
				switch cmd.Args[0].Lit() {
				case "else", "in":
					valid = false
				}
			}
		case *syntax.IfClause:
			// An else branch cannot itself have an elif or another else.
			valid = cmd.ThenPos.IsValid() || cmd.Else == nil
		case *syntax.CoprocClause:
			valid = coprocCommand(cmd)
		case *syntax.CmdSubst:
			valid = backquoteFraming(cmd)
		case *syntax.ArithmExp:
			valid = arithmeticQuotes(cmd.X)
		case *syntax.ArithmCmd:
			valid = arithmeticQuotes(cmd.X)
		case *syntax.CStyleLoop:
			valid = arithmeticQuotes(cmd.Init) && arithmeticQuotes(cmd.Cond) && arithmeticQuotes(cmd.Post)
		case *syntax.ParamExp:
			if cmd.Slice != nil {
				valid = arithmeticQuotes(cmd.Slice.Offset) && arithmeticQuotes(cmd.Slice.Length)
			}
		case *syntax.UnaryArithm:
			if cmd.Op == syntax.Inc || cmd.Op == syntax.Dec {
				valid = arithmeticTarget(cmd.X)
			}
		case *syntax.FuncDecl:
			if cmd.Name == nil || cmd.Body == nil || cmd.Body.Negated {
				valid = false
				break
			}
			switch cmd.Body.Cmd.(type) {
			case *syntax.Block, *syntax.Subshell, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause, *syntax.TestClause, *syntax.ArithmCmd:
			default:
				valid = false
			}
		case *syntax.BinaryCmd:
			// A standalone time (also time -p) is valid, but it cannot be
			// followed immediately by a pipeline or boolean operator.
			if emptyTimedPipeline(cmd.X) {
				valid = false
			}
		case *syntax.TimeClause:
			if cmd.Stmt != nil {
				// Pipelines are nested inside the time clause, whereas && and
				// || wrap it. Both shapes need a command after time's options.
				if pipeline, ok := cmd.Stmt.Cmd.(*syntax.BinaryCmd); ok && emptyTimeCommand(pipeline.X) {
					valid = false
				}
			}
		}
		return valid
	})
	return valid
}

// The parser removes only one level of backquote escaping. At deeper nesting,
// escaped backquotes can remain literal AST words even though Bash reevaluates
// them as shell syntax. Deny this unsupported residue, including malformed inner
// code, rather than silently skip commands hidden below a compound statement.
func backquoteFraming(sub *syntax.CmdSubst) bool {
	if !sub.Backquotes {
		return true
	}
	valid := true
	for _, stmt := range sub.Stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if !valid {
				return false
			}
			switch n := node.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst:
				return false // Each substitution has its own escaping context.
			case *syntax.Lit:
				valid = !strings.Contains(n.Value, "\\`")
			}
			return valid
		})
	}
	return valid
}

// A redirected simple coprocess can have its executable in Name rather than
// Stmt.Cmd. An adjacent unquoted descriptor number is not an executable, though
// the parser also puts it in Name (coproc 1>&1).
func coprocCommand(cmd *syntax.CoprocClause) bool {
	if cmd.Stmt == nil {
		return false
	}
	if cmd.Name != nil && coprocReservedWord(cmd.Name) {
		return false
	}
	if cmd.Stmt.Cmd != nil {
		if cmd.Name != nil {
			// Only a compound command can follow a coprocess name. The parser
			// also accepts names before time, declarations and let, losing the
			// executable's actual argv. Those shapes cannot certify a command.
			if !coprocCompound(cmd.Stmt.Cmd) {
				return false
			}
		}
		return coprocHead(cmd.Stmt)
	}
	if cmd.Name == nil {
		return false
	}
	return !coprocDescriptor(cmd.Name, cmd.Stmt.Redirs)
}

// The parser can consume the first descriptor as Name, then prepend it to a
// following call's argv. Adjacency and literal digits distinguish a descriptor
// from a quoted/escaped or whitespace-separated numeric executable name.
func coprocDescriptor(word *syntax.Word, redirs []*syntax.Redirect) bool {
	name := word.Lit()
	if name == "" || len(redirs) == 0 || redirs[0].N != nil || word.End().Offset() != redirs[0].OpPos.Offset() {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Restore an initial descriptor without mutating the parsed tree, including
// the leftmost call of a coprocess pipeline. Later descriptors parse normally.
func coprocStatement(stmt *syntax.Stmt) *syntax.Stmt {
	copy := *stmt
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		if len(cmd.Args) > 0 && coprocDescriptor(cmd.Args[0], stmt.Redirs) {
			call := *cmd
			call.Args = cmd.Args[1:]
			copy.Cmd = &call
			redirect := *stmt.Redirs[0]
			redirect.N = &syntax.Lit{Value: cmd.Args[0].Lit()}
			copy.Redirs = slices.Clone(stmt.Redirs)
			copy.Redirs[0] = &redirect
		}
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			pipeline := *cmd
			pipeline.X = coprocStatement(cmd.X)
			copy.Cmd = &pipeline
		}
	}
	return &copy
}

func coprocCompound(cmd syntax.Command) bool {
	switch cmd := cmd.(type) {
	case *syntax.Block, *syntax.Subshell, *syntax.IfClause, *syntax.WhileClause, *syntax.ForClause, *syntax.CaseClause, *syntax.TestClause, *syntax.ArithmCmd:
		return true
	case *syntax.BinaryCmd:
		return (cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll) && coprocCompound(cmd.X.Cmd)
	}
	return false
}

// Coprocess parsing can leave reserved words in a call or in Name even though
// Bash rejects them in that position. Quoted/escaped executable names are inert.
func coprocReservedWord(word *syntax.Word) bool {
	switch word.Lit() {
	case "then", "elif", "else", "fi", "do", "done", "esac", "in", "select", "!", "}", "]]":
		return true
	}
	return false
}

func coprocHead(stmt *syntax.Stmt) bool {
	switch cmd := stmt.Cmd.(type) {
	case *syntax.CallExpr:
		args := cmd.Args
		if len(args) > 0 && coprocDescriptor(args[0], stmt.Redirs) {
			args = args[1:]
			if len(args) == 0 {
				return false
			}
		}
		return len(cmd.Assigns) != 0 || len(args) == 0 || !coprocReservedWord(args[0])
	case *syntax.BinaryCmd:
		return coprocHead(cmd.X)
	case *syntax.FuncDecl, *syntax.CoprocClause:
		// These are not Bash compound commands in a coprocess head, despite
		// the parser accepting them as such. Nested bodies are checked normally.
		return false
	}
	return true
}

// Quotes do not make arithmetic operands inert in Bash. Reject the unsupported
// quoted grammar like the Bash guard, rather than skip expansions hidden in it.
// Parameter default and replacement words inherit this conservative check,
// including nested indices and slices. Command substitutions start a separate
// quoting context and are checked by the normal framing and word walkers.
func arithmeticQuotes(expr syntax.ArithmExpr) bool {
	if expr == nil {
		return true
	}
	valid := true
	syntax.Walk(expr, func(node syntax.Node) bool {
		if !valid {
			return false
		}
		switch node.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			valid = false
		case *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		}
		return valid
	})
	return valid
}

func emptyTimedPipeline(stmt *syntax.Stmt) bool {
	if stmt == nil || len(stmt.Redirs) > 0 {
		return false
	}
	timed, ok := stmt.Cmd.(*syntax.TimeClause)
	if !ok {
		return false
	}
	return emptyTimeCommand(timed.Stmt)
}

func emptyTimeCommand(stmt *syntax.Stmt) bool {
	if stmt == nil {
		return true
	}
	if len(stmt.Redirs) > 0 {
		return false
	}
	if stmt.Cmd == nil {
		return true
	}
	// The parser leaves Bash's unquoted option terminator as a command,
	// including any following negation or nested time keywords.
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) == 0 && len(call.Args) > 0 && call.Args[0].Lit() == "--" {
		words := call.Args[1:]
		for len(words) > 0 {
			switch words[0].Lit() {
			case "!":
				words = words[1:]
			case "time":
				words = words[1:]
				if len(words) > 0 && words[0].Lit() == "-p" {
					words = words[1:]
				}
				if len(words) > 0 && words[0].Lit() == "--" {
					words = words[1:]
				}
			default:
				return false
			}
		}
		return true
	}
	return emptyTimedPipeline(stmt)
}

// The parser accepts numeric increment operands even though Bash rejects them.
// Array indices are still traversed for active substitutions by the normal walk.
func arithmeticTarget(expr syntax.ArithmExpr) bool {
	word, ok := expr.(*syntax.Word)
	if !ok || len(word.Parts) != 1 {
		return false
	}
	if index, ok := word.Parts[0].(*syntax.ParamExp); ok {
		return index.Short && index.Index != nil && !index.Dollar.IsValid() && index.Param != nil && syntax.ValidName(index.Param.Value)
	}
	return syntax.ValidName(word.Lit())
}
