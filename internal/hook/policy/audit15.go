package policy

import (
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
	"github.com/avhn/secret/internal/hook/search"
	"mvdan.cc/sh/v3/syntax"
)

func packageLeadingOptions(args []string) []string {
	for len(args) > 0 {
		v := args[0]
		if optionIn("-C --dir --filter", v) {
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
			continue
		}
		if optionIn("-r --recursive -w --workspace-root", v) || strings.HasPrefix(v, "--dir=") || strings.HasPrefix(v, "--filter=") || strings.HasPrefix(v, "--recursive=") || strings.HasPrefix(v, "--workspace-root=") || strings.HasPrefix(v, "-C") && len(v) > 2 {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func rgOutputOnly(args []string) bool {
	for _, arg := range args {
		if optionIn("-l --files --files-with-matches --files-without-match --count --count-matches -c", arg) || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "lc") {
			return true
		}
	}
	return false
}

func rgPublicSelector(args []string) bool {
	narrow := false
	for i := 0; i < len(args); i++ {
		v := args[i]
		if optionIn("-g --glob --iglob", v) {
			i++
			if i >= len(args) {
				return false
			}
			v = args[i]
		} else if strings.HasPrefix(v, "--glob=") || strings.HasPrefix(v, "--iglob=") {
			_, v, _ = strings.Cut(v, "=")
		} else {
			continue
		}
		if strings.HasPrefix(v, "!") {
			continue
		}
		if search.Selector(v) {
			return false
		}
		narrow = true
	}
	return narrow
}

func kubernetesSecretResource(value string) bool {
	for _, resource := range strings.Split(value, ",") {
		kind, _, _ := strings.Cut(resource, "/")
		if optionIn("secret secrets", kind) {
			return true
		}
	}
	return false
}

// These commands give env a documented data role, not a launcher slot. Keep
// inspecting their other opaque arguments without recasting that data as code.
func environmentDataArgs(name string, args []string) []string {
	data := optionIn("jest vitest pytest grep egrep fgrep", name) || name == "python3" && len(args) >= 2 && args[0] == "-m" && args[1] == "venv" || name == "go" && len(args) > 0 && args[0] == "env" || name == "vercel" && len(args) > 1 && args[0] == "env" && args[1] == "ls" || name == "npm" && len(args) > 0 && args[0] == "test"
	if !data {
		return args
	}
	filtered := append([]string(nil), args...)
	for i, value := range filtered {
		if optionIn("env printenv", value) || name == "pytest" && i > 0 && args[i-1] == "-k" && strings.Contains(value, "env") {
			filtered[i] = "environment-data"
		}
	}
	return filtered
}

// fd lists names until an exec option supplies a child. A potentially protected
// result is supplied to that child as a synthetic path, just like find -exec.
func (a *analyzer) fdCommand(args []string, depth int, cwd string) {
	selector := ""
	globFilter := false
	var extensions []string
	childAt := -1
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if optionIn("-x --exec -X --exec-batch", arg) {
			childAt = i + 1
			break
		}
		if optionIn("-e --extension", arg) && i+1 < len(args) {
			i++
			selector = "*." + strings.TrimPrefix(args[i], ".")
			extensions = append(extensions, selector)
			globFilter = true
			continue
		}
		if strings.HasPrefix(arg, "--extension=") {
			selector = "*." + strings.TrimPrefix(strings.TrimPrefix(arg, "--extension="), ".")
			extensions = append(extensions, selector)
			globFilter = true
			continue
		}
		if optionIn("-g --glob", arg) {
			if i+1 < len(args) {
				i++
				selector = args[i]
				globFilter = true
			}
			continue
		}
		if strings.HasPrefix(arg, "--glob=") {
			selector = strings.TrimPrefix(arg, "--glob=")
			globFilter = true
			continue
		}
		if !strings.HasPrefix(arg, "-") && selector == "" {
			selector = arg
		}
	}
	if childAt < 0 {
		return
	}
	if childAt >= len(args) {
		a.reason = roles.Indeterminate
		return
	}
	child := append([]string(nil), args[childAt:]...)
	for i, v := range child {
		if v == ";" {
			child = child[:i]
			break
		}
	}
	protectedResults := !globFilter || selector == "" || search.Selector(selector) || search.FilteredScope(".", selector, "", cwd, a.home) != ""
	// Repeated extensions are alternatives, not successive restrictions.
	for _, extension := range extensions {
		if search.Selector(extension) || search.FilteredScope(".", extension, "", cwd, a.home) != "" {
			protectedResults = true
		}
	}
	if protectedResults {
		selected := filepath.ToSlash(filepath.Join(cwd, ".env"))
		if cwd == "" {
			selected = "/synthetic/.env"
		}
		replaced := false
		for i, v := range child {
			if v == "{}" {
				child[i] = selected
				replaced = true
			}
		}
		if !replaced {
			child = append(child, selected)
		}
	}
	a.command(child, depth+1, cwd, false)
}

// A conjunctive name filter can certify the names piped to xargs. Other find
// expressions keep the existing conservative stdin-source policy.
func (a *analyzer) filteredFindPipe(upstream, downstream *syntax.Stmt, cwd string) bool {
	if commandName(upstream) != "find" || commandName(downstream) != "xargs" {
		return false
	}
	call, ok := upstream.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	selector := ""
	roots := []string{}
	predicates := false
	for i := 1; i < len(call.Args); i++ {
		v := literal(call.Args[i])
		if v == "" {
			return false
		}
		if optionIn("-name -iname", v) {
			predicates = true
			i++
			if i >= len(call.Args) {
				return false
			}
			selector = literal(call.Args[i])
			continue
		}
		if optionIn("-print -print0", v) {
			predicates = true
			continue
		}
		if v == "-type" {
			predicates = true
			i++
			if i >= len(call.Args) || literal(call.Args[i]) != "f" {
				return false
			}
			continue
		}
		if v == "-P" && !predicates {
			continue
		}
		if strings.HasPrefix(v, "-") || predicates {
			return false
		}
		roots = append(roots, v)
	}

	if selector == "" || search.Selector(selector) {
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		if search.FilteredScope(root, selector, "", cwd, a.home) != "" {
			return false
		}
	}
	return true
}
