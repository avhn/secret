package policy

import (
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// Shell snapshots can enable expand_aliases. Keep literal alternatives rather
// than trusting a later (possibly conditional) definition to replace a reader.
// Directory-changing or unresolved definitions invalidate subsequent cwd proof.
func (a *analyzer) defineAliases(args []string, unknown bool, cwd string) string {
	if unknown {
		cwd = ""
	}
	for _, arg := range args {
		name, source, definition := strings.Cut(arg, "=")
		if !definition || strings.HasPrefix(name, "-") {
			continue
		}
		if a.aliases == nil {
			a.aliases = make(map[string][]string)
		}
		if !slices.Contains(a.aliases[name], source) {
			a.aliases[name] = append(slices.Clone(a.aliases[name]), source)
		}
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
		if err != nil {
			cwd = ""
			continue
		}
		syntax.Walk(file, func(node syntax.Node) bool {
			if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
				name := flowCommandName(&syntax.Stmt{Cmd: call})
				if name == "" || name == "cd" || name == "pushd" || name == "popd" || name == "eval" {
					cwd = ""
				}
			}
			return true
		})
	}
	return cwd
}

// Resolve directory effects at the use site, since a literal alias can name a
// function or another alias defined after it. Share the normal recursion and
// flow budgets; unresolved command syntax cannot certify a stable directory.
func (a *analyzer) aliasDirectoryUncertain(source string, depth int, active map[string]bool) bool {
	a.flowSteps++
	if depth >= 4 || a.flowSteps > maxFlowSteps {
		return true
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		return true
	}
	uncertain := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if uncertain {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			name := flowCommandName(&syntax.Stmt{Cmd: call})
			if literal(unwrapCall(call).Args[0]) == "" || optionIn("cd pushd popd dirs eval", name) {
				uncertain = true
			}
			for _, body := range a.functions[name] {
				uncertain = uncertain || a.functionDirectoryChanges(body, depth+1) > 0
			}
			if !active[name] {
				active[name] = true
				for _, body := range a.aliases[name] {
					uncertain = uncertain || a.aliasDirectoryUncertain(body, depth+1, active)
				}
				delete(active, name)
			}
		}
		return true
	})
	return uncertain
}

// Replay an alias as shell source, not as an executable name. Its literal body
// may supply reader operands or contain several commands. Preserve the caller's
// assignments and redirects, and suppress recursive expansion of the same name.
func (a *analyzer) aliasStates(stmt *syntax.Stmt, depth int, cwd string) ([]string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, false
	}
	unwrapped := unwrapCall(call)
	name := literal(unwrapped.Args[0])
	bodies := a.aliases[name]
	if len(unwrapped.Args) != len(call.Args) {
		// command/builtin suppress shell alias expansion. Retain the guard's
		// conservative cwd uncertainty for live directory-changing aliases,
		// including bodies which call a subsequently defined function. Query
		// options are not unwrapped, and public aliases do not change cwd.
		for _, body := range bodies {
			if a.aliasDirectoryUncertain(body, depth, map[string]bool{name: true}) {
				a.singleStmt([]*syntax.Stmt{stmt}, depth, cwd)
				return []string{""}, true
			}
		}
		return nil, false
	}
	if len(bodies) == 0 || a.activeAliases[name] {
		return nil, false
	}
	if depth >= 4 {
		a.reason = roles.Indeterminate
		return nil, true
	}
	if a.activeAliases == nil {
		a.activeAliases = make(map[string]bool)
	}
	a.activeAliases[name] = true
	defer delete(a.activeAliases, name)
	var prefix, suffix strings.Builder
	for _, assign := range call.Assigns {
		syntax.NewPrinter().Print(&prefix, assign)
		prefix.WriteByte(' ')
	}
	suffix.WriteByte(' ')
	suffix.WriteString(a.rawArgs(call.Args[1:]))
	for _, redirect := range stmt.Redirs {
		suffix.WriteByte(' ')
		syntax.NewPrinter().Print(&suffix, redirect)
	}
	dirs := []string{cwd}
	for _, body := range bodies {
		source := prefix.String() + body + suffix.String()
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
		if err != nil {
			a.reason = roles.Indeterminate
			return nil, true
		}
		dirs = a.cwdUnion(dirs, a.statementStates(file.Stmts, depth+1, []string{cwd}))
		if a.reason != "" {
			break
		}
	}
	return dirs, true
}
