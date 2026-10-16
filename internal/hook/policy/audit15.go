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
		if optionIn("-C --dir --filter -F", v) {
			if len(args) < 2 {
				return nil
			}
			args = args[2:]
			continue
		}
		if optionIn("-r --recursive -w --workspace-root -s --silent -q --quiet", v) || strings.HasPrefix(v, "--dir=") || strings.HasPrefix(v, "--filter=") || strings.HasPrefix(v, "--recursive=") || strings.HasPrefix(v, "--workspace-root=") || strings.HasPrefix(v, "-C") && len(v) > 2 || strings.HasPrefix(v, "-F") && len(v) > 2 {
			args = args[1:]
			continue
		}
		break
	}
	return args
}

func rgOutputOnly(args []string) bool {
	for _, arg := range args {
		if optionIn("-l --files --files-with-matches --files-without-match --count --count-matches -c -q --quiet", arg) || strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "lcq") {
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
		if !search.CanNarrow(v) {
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
func (a *analyzer) environmentDataArgs(name string, args []string) []string {
	data := optionIn("jest vitest pytest venv grep egrep fgrep", name) || name == "python3" && len(args) >= 2 && args[0] == "-m" && args[1] == "venv" || name == "go" && len(args) > 0 && args[0] == "env" || name == "vercel" && len(args) > 1 && args[0] == "env" && args[1] == "ls" || name == "npm" && len(args) > 0 && args[0] == "test"
	if name == "npm" {
		options := packageExecOptions{}
		leading := a.packageExecOptions(name, args, &options)
		if len(leading) > 0 && optionIn("run run-script rum urn", leading[0]) {
			script := a.packageExecOptions(name, leading[1:], &options)
			data = data || !options.bad && len(script) > 0 && !optionIn("env printenv", script[0])
		}
	}
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

// fdScope parses the selector and every search root before the execution slot.
// Regex patterns without an extension proof remain conservative; -g is boolean.
func (a *analyzer) fdScope(args []string, cwd string) (child []string, dir string, protected bool) {
	dir = cwd
	selector, patternSet, globFilter := "", false, false
	var extensions, roots []string
	uncertain := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if optionIn("-x --exec -X --exec-batch", arg) {
			child = append([]string(nil), args[i+1:]...)
			if len(child) == 0 {
				uncertain = true
			}
			break
		}
		if optionIn("-g --glob", arg) {
			globFilter = true
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		if optionIn("-e --extension --search-path --base-directory -E --exclude", key) {
			if !attached {
				i++
				if i >= len(args) {
					uncertain = true
					break
				}
				value = args[i]
			}
			switch key {
			case "-e", "--extension":
				extensions = append(extensions, "*."+strings.TrimPrefix(value, "."))
			case "--search-path":
				roots = append(roots, value)
			case "--base-directory":
				dir = a.resolve(value, dir)
			}
			continue
		}
		if strings.HasPrefix(arg, "-") {
			if !optionIn("-H --hidden -I --no-ignore -u --unrestricted -L --follow -0 --print0 -a --absolute-path -l --list-details --", arg) {
				uncertain = true
			}
			continue
		}
		if !patternSet {
			selector, patternSet = arg, true
		} else {
			roots = append(roots, arg)
		}
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	filters := extensions
	if len(filters) == 0 && globFilter && patternSet {
		filters = []string{selector}
	}
	protected = uncertain || patternSet && selector != "" && selector != "." && a.protectedGlob(strings.ToLower(selector), dir)
	for _, root := range roots {
		if len(filters) == 0 && a.treeProtectedAll(root, dir) {
			protected = true
		}
		for _, filter := range filters {
			if a.protectedGlob(strings.ToLower(filter), dir) || search.FilteredScopeConfigured(root, filter, "", dir, a.home, a.credentialConfig()) != "" {
				protected = true
			}
		}
	}
	return child, dir, protected
}

// fd execution consumes a synthetic protected path whenever any selected root
// cannot certify public results. Names-only fd remains a metadata operation.
func (a *analyzer) fdCommand(args []string, depth int, cwd string) {
	child, dir, protected := a.fdScope(args, cwd)
	if len(child) == 0 {
		return
	}
	if protected {
		selected := filepath.ToSlash(filepath.Join(dir, ".env"))
		if dir == "" {
			selected = "/synthetic/.env"
		}
		replaced := false
		for i, v := range child {
			if v == "{}" {
				child[i], replaced = selected, true
			}
		}
		if !replaced {
			child = append(child, selected)
		}
	}
	a.command(child, depth+1, dir, false)
}

// A filtered fd stream is certified by the same root and selector proof as -x.
func (a *analyzer) filteredFDPipe(upstream, downstream *syntax.Stmt, depth int, cwd string) bool {
	if !optionIn("fd fdfind", commandName(upstream)) || commandName(downstream) != "xargs" {
		return false
	}
	call, ok := upstream.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	words, known := a.listingWords(call, cwd)
	if !known {
		return false
	}
	child, dir, protected := a.fdScope(words[1:], cwd)
	if len(child) != 0 {
		return false
	}
	if protected {
		a.protectedXargsPipe(downstream, depth, dir)
		return false
	}
	return true
}

func (a *analyzer) protectedXargsPipe(downstream *syntax.Stmt, depth int, cwd string) {
	call, ok := downstream.Cmd.(*syntax.CallExpr)
	if !ok {
		a.reason = roles.Indeterminate
		return
	}
	words, known := a.listingWords(call, cwd)
	if !known {
		a.reason = roles.Indeterminate
		return
	}
	child, dir, shell := a.utilityChild("xargs", words[1:], cwd)
	if shell || !a.metadataChild(child, depth+1, dir) {
		a.reason = roles.FileInput
	}
}

// A conjunctive name filter narrows a find stream, but every producer root
// must still be scanned. Unfiltered streams use the complete root scope.
func (a *analyzer) filteredFindPipe(upstream, downstream *syntax.Stmt, depth int, cwd string) bool {
	if commandName(upstream) != "find" || commandName(downstream) != "xargs" {
		return false
	}
	call, ok := upstream.Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	words, known := a.listingWords(call, cwd)
	if !known {
		return false
	}
	selector := ""
	roots := []string{}
	predicates := false
	for i := 1; i < len(words); i++ {
		v := words[i]
		if v == "" {
			return false
		}
		if optionIn("-name -iname", v) {
			predicates = true
			i++
			if i >= len(words) {
				return false
			}
			selector = words[i]
			continue
		}
		if optionIn("-print -print0", v) {
			predicates = true
			continue
		}
		if v == "-type" {
			predicates = true
			i++
			if i >= len(words) || words[i] != "f" {
				return false
			}
			continue
		}
		if optionIn("-P -L -H", v) && !predicates {
			continue
		}
		if strings.HasPrefix(v, "-") || predicates {
			return false
		}
		roots = append(roots, v)
	}

	if selector != "" && a.protectedGlob(strings.ToLower(selector), cwd) {
		a.protectedXargsPipe(downstream, depth, cwd)
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		if selector == "" && a.treeProtectedAll(root, cwd) || selector != "" && search.FilteredScopeConfigured(root, selector, "", cwd, a.home, a.credentialConfig()) != "" {
			a.protectedXargsPipe(downstream, depth, cwd)
			return false
		}
	}
	return true
}
