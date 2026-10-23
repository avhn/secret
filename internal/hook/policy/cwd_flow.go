package policy

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// Directory alternatives are precise, not widened: a set beyond this cap is
// indeterminate. Conditional relative cd statements can double the set, so a
// larger cap admits longer alternative chains without changing that decision.
const maxWorkingDirectories = 128
const maxFlowSteps = 4096

// maxFlowWork bounds the per-directory statement replays across one analysis,
// whatever the directory cap. The 256-word budget at the earlier 32-directory
// cap allowed about 8192 replays; this keeps the total within twice that.
const maxFlowWork = 16384

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
	if a.functionRoots == nil {
		a.functionRoots = make(map[*syntax.Stmt]string)
	}
	if root, exists := a.functionRoots[decl.Body]; exists && root != cwd {
		a.functionRoots[decl.Body] = ""
	} else if !exists {
		a.functionRoots[decl.Body] = cwd
	}
	parent, aliases := a.functions, a.aliases
	a.functions, a.aliases = maps.Clone(parent), maps.Clone(aliases)
	a.functionStates(decl.Body, depth+1, []string{cwd})
	a.functions, a.aliases = parent, aliases
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
	var dirs []string
	if block, ok := body.Cmd.(*syntax.Block); ok && len(body.Redirs) == 0 {
		dirs = a.statementStates(block.Stmts, depth, states)
	} else {
		flow := a.statementFlow(body, depth, states)
		dirs = a.cwdUnion(flow.success, flow.failure)
	}
	// Match the retained guard's bounded function-effect proof: only one
	// direct directory change at the definition cwd has a precise target.
	changes := a.functionDirectoryChanges(body, depth)
	if changes > 1 || changes == 1 && (len(states) != 1 || a.functionRoots[body] != states[0]) {
		dirs = a.cwdUnion(dirs, []string{""})
	}
	return dirs
}

// Count current-shell directory effects, capped at two for uncertainty. Child
// shells and uncalled nested definitions cannot change the function's caller.
func (a *analyzer) functionDirectoryChanges(body *syntax.Stmt, depth int) int {
	if depth > 4 {
		return 2
	}
	changes := 0
	syntax.Walk(body, func(node syntax.Node) bool {
		if changes > 1 {
			return false
		}
		switch cmd := node.(type) {
		case *syntax.FuncDecl, *syntax.Subshell, *syntax.CoprocClause:
			return false
		case *syntax.Stmt:
			return !cmd.Background
		case *syntax.BinaryCmd:
			return cmd.Op != syntax.Pipe && cmd.Op != syntax.PipeAll
		case *syntax.CallExpr:
			name := flowCommandName(&syntax.Stmt{Cmd: cmd})
			switch name {
			case "cd", "pushd", "popd", "dirs":
				changes++
			default:
				for _, nested := range a.functions[name] {
					if a.functionDirectoryChanges(nested, depth+1) > 0 {
						changes = 2
						break
					}
				}
			}
			return false
		}
		return true
	})
	return changes
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
				dir = a.canonicalCWD(dir)
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

// Branch success/failure joins repeatedly canonicalize the same directories.
// Retain the existing physical-or-clean result for this analysis, including
// failed lookups. Key the raw spelling so symlink/.. paths remain distinct.
func (a *analyzer) canonicalCWD(dir string) string {
	if canonical, ok := a.cwdPaths[dir]; ok {
		return canonical
	}
	check := a.cwdPathCheck
	if check == nil {
		check = filepath.EvalSymlinks
	}
	canonical, err := check(dir)
	if err != nil {
		canonical = filepath.Clean(dir)
	}
	if a.cwdPaths == nil {
		a.cwdPaths = make(map[string]string)
	}
	if len(a.cwdPaths) < 4096 {
		a.cwdPaths[dir] = canonical
	}
	return canonical
}

func (a *analyzer) statementFlow(stmt *syntax.Stmt, depth int, states []string) cwdFlow {
	if a.reason != "" || len(states) == 0 {
		return cwdFlow{}
	}
	priorBranch := a.credentialBranch
	switch cmd := stmt.Cmd.(type) {
	case *syntax.IfClause, *syntax.CaseClause, *syntax.WhileClause, *syntax.ForClause, *syntax.Subshell, *syntax.FuncDecl:
		a.credentialBranch = true
	case *syntax.BinaryCmd:
		a.credentialBranch = true
	case *syntax.CallExpr:
		if len(cmd.Args) > 0 && len(cmd.Assigns) > 0 {
			a.credentialBranch = true
		}
	}
	defer func() { a.credentialBranch = priorBranch }()
	a.flowSteps++
	a.flowWork += len(states)
	if a.flowSteps > maxFlowSteps || a.flowWork > maxFlowWork {
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
	ghChild := childScope
	if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) > 0 {
		name := flowCommandName(stmt)
		ghChild = ghChild || len(a.functions[name]) == 0 && !optionIn("eval export declare typeset local readonly source .", name)
	}
	if ghChild {
		restore := a.scopedGHConfig()
		defer restore()
	}
	if childScope {
		parent, aliases := a.functions, a.aliases
		a.functions, a.aliases = maps.Clone(parent), maps.Clone(aliases)
		defer func() { a.functions, a.aliases = parent, aliases }()
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
		if dirs, aliased := a.aliasStates(stmt, depth, cwd); aliased {
			result.success = append(result.success, dirs...)
			result.failure = append(result.failure, dirs...)
			continue
		}
		next := a.singleStmt([]*syntax.Stmt{stmt}, depth, cwd)
		if name == "eval" && a.reason == "" {
			dirs := a.evalStates(stmt, depth, cwd)
			result.success = append(result.success, dirs...)
			result.failure = append(result.failure, dirs...)
			continue
		}
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

// eval executes in the current shell. Replay its bounded literal source so
// directory effects, including defined function calls, reach later statements.
func (a *analyzer) evalStates(stmt *syntax.Stmt, depth int, cwd string) []string {
	if depth >= 4 {
		a.reason = roles.Indeterminate
		return nil
	}
	call := unwrapCall(stmt.Cmd.(*syntax.CallExpr))
	var words []string
	for _, word := range call.Args[1:] {
		values, known := a.expandWord(word, cwd)
		if !known {
			return a.cwdUnion([]string{cwd, ""})
		}
		words = append(words, values...)
	}
	if len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	source := strings.Join(words, " ")
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		a.reason = roles.Indeterminate
		return nil
	}
	dirs := a.cwdUnion([]string{cwd}, a.statementStates(file.Stmts, depth+1, []string{cwd}))
	// Dynamic current-shell eval source cannot certify retained state. Child
	// substitutions and subshells still cannot move the caller's directory.
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			return false
		case *syntax.ArithmExp:
			// Arithmetic can assign shell variables such as CDPATH.
			dirs = a.cwdUnion(dirs, []string{""})
		case *syntax.ParamExp:
			if node.Param == nil {
				dirs = a.cwdUnion(dirs, []string{""})
			} else if _, known := a.staticVariable(node.Param.Value); !known {
				dirs = a.cwdUnion(dirs, []string{""})
			}
		}
		return true
	})
	return dirs
}
