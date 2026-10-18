package policy

import "mvdan.cc/sh/v3/syntax"

// The parser accepts some AST shapes that Bash rejects. Certify these framing
// rules before walking commands, including inactive branches and substitutions.
func bashFraming(root syntax.Node) bool {
	valid := true
	syntax.Walk(root, func(node syntax.Node) bool {
		if !valid {
			return false
		}
		switch cmd := node.(type) {
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

// A redirected simple coprocess can have its executable in Name rather than
// Stmt.Cmd. An adjacent unquoted descriptor number is not an executable, though
// the parser also puts it in Name (coproc 1>&1).
func coprocCommand(cmd *syntax.CoprocClause) bool {
	if cmd.Stmt == nil {
		return false
	}
	if cmd.Stmt.Cmd != nil {
		return true
	}
	if cmd.Name == nil {
		return false
	}
	name := cmd.Name.Lit()
	if name == "" || len(cmd.Stmt.Redirs) == 0 || cmd.Name.End().Offset() != cmd.Stmt.Redirs[0].OpPos.Offset() {
		return true
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return true
		}
	}
	return false
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
