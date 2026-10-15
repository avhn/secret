package policy

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

const maxWorkingDirectories = 32
const maxFlowSteps = 4096

type cwdFlow struct{ success, failure []string }

// A definition is checked for prohibited operations without moving its caller
// or publishing definitions nested in an uncalled body.
func (a *analyzer) defineFunction(decl *syntax.FuncDecl, depth int, cwd string) {
	if a.functions == nil {
		a.functions = make(map[string][]*syntax.Stmt)
	}
	// Retain alternative definitions: a later declaration may be conditional.
	// Copy on insertion so a child scope cannot change a parent's slice.
	bodies := a.functions[decl.Name.Value]
	if !slices.Contains(bodies, decl.Body) {
		a.functions[decl.Name.Value] = append(slices.Clone(bodies), decl.Body)
	}
	parent := a.functions
	a.functions = maps.Clone(parent)
	a.functionStates(decl.Body, depth+1, []string{cwd})
	a.functions = parent
}

// Match the policy's transparent command/builtin normalization, including its
// conservative function-call variants. Executable paths are not function names.
func (a *analyzer) calledFunctions(stmt *syntax.Stmt, cwd string) []*syntax.Stmt {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 || len(a.functions) == 0 {
		return nil
	}
	call = unwrapCall(call)
	values, known := a.expandWord(call.Args[0], cwd)
	if !known || len(values) == 0 {
		return nil
	}
	return a.functions[values[0]]
}

// Replay a body at the call cwd, preserving all bounded directory alternatives.
// A function's outer braces do not add a zero-execution path as a branch does.
func (a *analyzer) functionStates(body *syntax.Stmt, depth int, states []string) []string {
	if a.reason != "" {
		return nil
	}
	if depth > 4 {
		a.reason = roles.Indeterminate
		return nil
	}
	if block, ok := body.Cmd.(*syntax.Block); ok && len(body.Redirs) == 0 {
		return a.statementStates(block.Stmts, depth, states)
	}
	flow := a.statementFlow(body, depth, states)
	return a.cwdUnion(flow.success, flow.failure)
}

// flowCommandName matches singleStmt's transparent wrapper normalization without
// changing the statement or its word provenance.
func flowCommandName(stmt *syntax.Stmt) string {
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
		call = unwrapCall(call)
		if len(call.Args) > 0 {
			return path.Base(literal(call.Args[0]))
		}
	}
	return ""
}

// Each subsequent statement is visited once per distinct possible cwd. Boolean
// branches retain success/failure paths so && never reads from a failed cd.
func (a *analyzer) stmts(stmts []*syntax.Stmt, depth int, cwd string) string {
	// Anchor the first statement exactly like its successors. Otherwise a
	// future Git root recorded before cwdUnion retains a symlink/volume alias
	// while later write targets use the physical cwd and miss that root.
	states := a.statementStates(stmts, depth, a.cwdUnion([]string{cwd}))
	if len(states) == 1 {
		return states[0]
	}
	return ""
}

// statementStates keeps alternatives intact across compound-command boundaries.
func (a *analyzer) statementStates(stmts []*syntax.Stmt, depth int, states []string) []string {
	for _, stmt := range stmts {
		flow := a.statementFlow(stmt, depth, states)
		states = a.cwdUnion(flow.success, flow.failure)
		// Preserve the modeled unconditional cd into an existing static
		// directory. Conditional cd outcomes still flow through the boolean
		// node above, and missing targets retain their failure directory.
		if flowCommandName(stmt) == "cd" && !stmt.Negated && !stmt.Background && len(flow.success) == 1 {
			if info, err := os.Stat(flow.success[0]); err == nil && info.IsDir() {
				states = flow.success
			}
		}
		if a.reason != "" {
			break
		}
	}
	return states
}

func (a *analyzer) cwdUnion(groups ...[]string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, group := range groups {
		for _, dir := range group {
			if dir != "" {
				if physical, err := filepath.EvalSymlinks(dir); err == nil {
					dir = physical
				} else {
					dir = filepath.Clean(dir)
				}
			}
			if !seen[dir] {
				seen[dir] = true
				result = append(result, dir)
			}
		}
	}
	if len(result) > maxWorkingDirectories {
		a.reason = roles.Indeterminate
		return nil
	}
	return result
}

func (a *analyzer) statementFlow(stmt *syntax.Stmt, depth int, states []string) cwdFlow {
	if a.reason != "" || len(states) == 0 {
		return cwdFlow{}
	}
	a.flowSteps++
	if a.flowSteps > maxFlowSteps {
		a.reason = roles.Indeterminate
		return cwdFlow{}
	}
	childScope := stmt.Background
	switch cmd := stmt.Cmd.(type) {
	case *syntax.Subshell, *syntax.CoprocClause:
		childScope = true
	case *syntax.BinaryCmd:
		childScope = childScope || cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll
	}
	if childScope {
		parent := a.functions
		a.functions = maps.Clone(parent)
		defer func() { a.functions = parent }()
	}
	if stmt.Background {
		// The asynchronous command still needs analysis, but its directory
		// changes happen in a child and cannot change the parent's cwd.
		child := *stmt
		child.Background = false
		a.statementFlow(&child, depth, states)
		return cwdFlow{states, states}
	}
	if len(stmt.Redirs) == 0 {
		switch cmd := stmt.Cmd.(type) {
		case *syntax.Block:
			dirs := a.cwdUnion(states, a.statementStates(cmd.Stmts, depth, states))
			return cwdFlow{dirs, dirs}
		case *syntax.WhileClause:
			// A statically false while condition cannot move the parent cwd.
			// Still analyze its body for prohibited operations, like other
			// syntactically present branches, without exporting its cd.
			if !cmd.Until && len(cmd.Cond) == 1 && flowCommandName(cmd.Cond[0]) == "false" && !cmd.Cond[0].Negated {
				conditions := a.statementStates(cmd.Cond, depth, states)
				a.statementStates(cmd.Do, depth, conditions)
				return cwdFlow{states, states}
			}
		case *syntax.IfClause:
			dirs := states
			for clause := cmd; clause != nil; clause = clause.Else {
				conditions := a.statementStates(clause.Cond, depth, dirs)
				branches := a.statementStates(clause.Then, depth, conditions)
				dirs = a.cwdUnion(dirs, conditions, branches)
			}
			return cwdFlow{dirs, dirs}
		}
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && len(stmt.Redirs) == 0 && (binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt) {
		left := a.statementFlow(binary.X, depth, states)
		var result cwdFlow
		if binary.Op == syntax.AndStmt {
			right := a.statementFlow(binary.Y, depth, left.success)
			result = cwdFlow{right.success, a.cwdUnion(left.failure, right.failure)}
		} else {
			right := a.statementFlow(binary.Y, depth, left.failure)
			result = cwdFlow{a.cwdUnion(left.success, right.success), right.failure}
		}
		if stmt.Negated {
			result.success, result.failure = result.failure, result.success
		}
		return result
	}
	var result cwdFlow
	name := flowCommandName(stmt)
	for _, cwd := range states {
		next := a.singleStmt([]*syntax.Stmt{stmt}, depth, cwd)
		if bodies := a.calledFunctions(stmt, cwd); len(bodies) > 0 && a.reason == "" {
			// A definition may be conditional, so keep the original cwd as
			// well as every body's effects. Do not infer status from its name.
			dirs := []string{cwd}
			for _, body := range bodies {
				dirs = a.cwdUnion(dirs, a.functionStates(body, depth+1, []string{cwd}))
				if a.reason != "" {
					break
				}
			}
			result.success = append(result.success, dirs...)
			result.failure = append(result.failure, dirs...)
			continue
		}
		if name != "false" {
			result.success = append(result.success, next)
		}
		if name != "true" && name != ":" {
			if name == "cd" || name == "pushd" || name == "popd" {
				result.failure = append(result.failure, cwd)
			} else {
				result.failure = append(result.failure, next)
			}
		}
		if a.reason != "" {
			break
		}
	}
	result.success = a.cwdUnion(result.success)
	result.failure = a.cwdUnion(result.failure)
	if stmt.Negated {
		result.success, result.failure = result.failure, result.success
	}
	return result
}
