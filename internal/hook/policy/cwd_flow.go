package policy

import (
	"os"
	"path/filepath"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

const maxWorkingDirectories = 32
const maxFlowSteps = 4096

type cwdFlow struct{ success, failure []string }

// Each subsequent statement is visited once per distinct possible cwd. Boolean
// branches retain success/failure paths so && never reads from a failed cd.
func (a *analyzer) stmts(stmts []*syntax.Stmt, depth int, cwd string) string {
	states := []string{cwd}
	for _, stmt := range stmts {
		flow := a.statementFlow(stmt, depth, states)
		states = a.cwdUnion(flow.success, flow.failure)
		// Preserve the modeled unconditional cd into an existing static
		// directory. Conditional cd outcomes still flow through the boolean
		// node above, and missing targets retain their failure directory.
		if commandName(stmt) == "cd" && !stmt.Negated && len(flow.success) == 1 {
			if info, err := os.Stat(flow.success[0]); err == nil && info.IsDir() {
				states = flow.success
			}
		}
		if a.reason != "" {
			break
		}
	}
	if len(states) == 1 {
		return states[0]
	}
	return ""
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
	for _, cwd := range states {
		next := a.singleStmt([]*syntax.Stmt{stmt}, depth, cwd)
		name := commandName(stmt)
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
