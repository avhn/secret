package policy

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Package selectors are launcher metadata, not the executable child. Consume
// their values before examining env/printenv or ordinary test-runner operands.
func packageRunnerOptions(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		if optionIn("-p --package", arg) {
			if len(args) == 0 {
				return nil
			}
			args = args[1:]
		}
	}
	return args
}

func packageCallOption(arg string) bool {
	return arg == "--call" || strings.HasPrefix(arg, "--call=") || strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--")
}

// listingWords applies the same bounded static expansion as command dispatch.
// In particular, dynamic roots cannot silently become the downstream cwd.
func (a *analyzer) listingWords(call *syntax.CallExpr, cwd string) ([]string, bool) {
	var words []string
	for _, word := range call.Args {
		values, known := a.expandWord(word, cwd)
		if !known {
			return nil, false
		}
		words = append(words, values...)
	}
	return words, len(words) > 0
}

// certifiedListingPipe proves the scope of the producer, not xargs's cwd.
// A recognized but uncertifiable listing still checks the xargs child against
// protected input. Metadata-only children need no file-content certification.
func (a *analyzer) certifiedListingPipe(upstream, downstream *syntax.Stmt, depth int, cwd string) bool {
	call, ok := downstream.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	name := strings.ToLower(path.Base(literal(unwrapCall(call).Args[0])))
	if _, wrapper := utilityTable[name]; name != "xargs" && name != "env" && !wrapper {
		return false
	}
	sink, sinkCWD, sinkOK := a.listingInvocation(downstream, cwd)
	if !sinkOK || strings.ToLower(path.Base(literal(sink.Args[0]))) != "xargs" {
		return false
	}
	down := *downstream
	down.Cmd = sink
	source, sourceCWD, sourceOK := a.listingInvocation(upstream, cwd)
	if original, ok := upstream.Cmd.(*syntax.CallExpr); ok && len(original.Assigns) != 0 {
		sourceOK = false
	}
	if !sourceOK {
		// An intervening pipeline or compound command does not certify an
		// unchanged name stream. Never let its listing fall back to cwd.
		if listingStage(upstream) {
			a.protectedXargsPipe(&down, depth, sinkCWD)
		}
		return false
	}
	name = strings.ToLower(path.Base(literal(source.Args[0])))
	if !optionIn("find fd fdfind ls git rg", name) {
		return false
	}
	words, known := a.listingWords(source, sourceCWD)
	if known && name == "git" && !containsWord(words[1:], "ls-files") || known && name == "rg" && !containsWord(words[1:], "--files") {
		return false
	}
	up := *upstream
	up.Cmd = source
	safe := false
	if known {
		switch name {
		case "find":
			safe = a.filteredFindPipe(&up, &down, depth, sourceCWD)
		case "fd", "fdfind":
			safe = a.filteredFDPipe(&up, &down, depth, sourceCWD)
		case "ls":
			safe = a.lsListingSafe(words[1:], sourceCWD)
		case "git":
			safe = a.gitListingSafe(words[1:], sourceCWD)
		case "rg":
			safe = a.rgListingSafe(words[1:], sourceCWD)
		}
	}
	if !safe {
		a.protectedXargsPipe(&down, depth, sinkCWD)
	}
	// Execution wrappers retain the pre-existing consumer check. Inert
	// command/builtin prefixes do not change the direct listing grammar.
	original, ok := upstream.Cmd.(*syntax.CallExpr)
	return safe && ok && strings.ToLower(path.Base(literal(unwrapCall(original).Args[0]))) == name
}

// Peel only modeled argv wrappers. Their child words are already statically
// expanded, so rebuilding literal AST words never evaluates shell text.
func (a *analyzer) listingInvocation(stmt *syntax.Stmt, cwd string) (*syntax.CallExpr, string, bool) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return nil, cwd, false
	}
	words, known := a.listingWords(unwrapCall(call), cwd)
	if !known {
		return nil, cwd, false
	}
	for level := 0; level < 5 && len(words) > 0; level++ {
		name := strings.ToLower(path.Base(words[0]))
		if name != "xargs" {
			if _, utility := utilityTable[name]; utility {
				child, dir, shell := a.utilityChild(name, words[1:], cwd)
				if shell || a.reason != "" {
					return nil, cwd, false
				}
				words, cwd = child, dir
				continue
			}
		}
		if optionIn("command builtin env", name) {
			words = words[1:]
			for len(words) > 0 {
				arg := words[0]
				if arg == "--" {
					words = words[1:]
					break
				}
				if optionIn("-i --ignore-environment -0 --null", arg) && name == "env" || arg == "-p" && name == "command" {
					words = words[1:]
					continue
				}
				if name == "env" && optionIn("-u --unset -C --chdir", arg) {
					if len(words) < 2 {
						return nil, cwd, false
					}
					if optionIn("-C --chdir", arg) {
						cwd = a.resolve(words[1], cwd)
					}
					words = words[2:]
					continue
				}
				if name == "env" && strings.HasPrefix(arg, "--chdir=") {
					cwd = a.resolve(strings.TrimPrefix(arg, "--chdir="), cwd)
					words = words[1:]
					continue
				}
				if name == "env" && strings.HasPrefix(arg, "--unset=") {
					words = words[1:]
					continue
				}
				if strings.HasPrefix(arg, "-") || name == "env" && strings.Contains(arg, "=") {
					return nil, cwd, false
				}
				break
			}
			continue
		}
		result := &syntax.CallExpr{}
		for _, word := range words {
			result.Args = append(result.Args, &syntax.Word{Parts: []syntax.WordPart{&syntax.SglQuoted{Value: word}}})
		}
		return result, cwd, true
	}
	return nil, cwd, false
}

// A transformed/compound listing stream cannot borrow a clean xargs cwd.
func listingStage(stmt *syntax.Stmt) bool {
	found := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if found {
			return false
		}
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			call = unwrapCall(call)
			name := strings.ToLower(path.Base(literal(call.Args[0])))
			found = optionIn("find fd fdfind ls", name)
			if name == "git" || name == "rg" || name == "env" || name == "timeout" || name == "sudo" {
				for _, word := range call.Args[1:] {
					value := literal(word)
					if value == "ls-files" || value == "--files" || optionIn("find fd fdfind ls", value) {
						found = true
					}
				}
			}
		}
		return !found
	})
	return found
}

func containsWord(words []string, want string) bool {
	for _, word := range words {
		if word == want {
			return true
		}
	}
	return false
}

func (a *analyzer) listingRootsSafe(roots []string, cwd string) bool {
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		if root == "" {
			return false
		}
		if a.treeProtectedAll(root, cwd) {
			return false
		}
	}
	return true
}

func (a *analyzer) lsListingSafe(args []string, cwd string) bool {
	var roots []string
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if strings.HasPrefix(arg, "--color=") || strings.HasPrefix(arg, "--quoting-style=") || strings.HasPrefix(arg, "--time-style=") || arg == "--group-directories-first" || !strings.HasPrefix(arg, "--") && strings.Trim(arg[1:], "aAbBcCdDfFgGhHiklLmMnNopqQrRsStTuUvwxX1") == "" {
				continue
			}
			return false
		}
		roots = append(roots, arg)
	}
	return a.listingRootsSafe(roots, cwd)
}

func (a *analyzer) gitListingSafe(args []string, cwd string) bool {
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"} {
		_, inline := a.env[key]
		_, inherited := os.LookupEnv(key)
		if inline || inherited {
			return false
		}
	}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "-C" {
			if len(args) == 0 || args[0] == "" {
				return false
			}
			cwd, args = a.resolve(args[0], cwd), args[1:]
		} else if strings.HasPrefix(arg, "-C") && len(arg) > 2 {
			cwd = a.resolve(arg[2:], cwd)
		} else if !optionIn("--no-pager --no-optional-locks", arg) {
			// Other global repository/configuration overrides need a broader
			// proof than a cwd-based names walk. Git dispatch checks them too.
			return false
		}
	}
	if len(args) == 0 || args[0] != "ls-files" {
		return false
	}
	for _, arg := range args[1:] {
		value := strings.ReplaceAll(arg, `\`, "/")
		// Parent/top/absolute pathspecs can list outside the -C directory.
		// That larger root is not established by this cwd-based proof.
		if path.IsAbs(value) || filepath.IsAbs(filepath.FromSlash(value)) || strings.HasPrefix(value, ":/") || strings.HasPrefix(value, ":(") || containsWord(strings.Split(value, "/"), "..") {
			return false
		}
	}
	return a.listingRootsSafe(nil, cwd)
}

func (a *analyzer) rgListingSafe(args []string, cwd string) bool {
	var roots []string
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			key, _, attached := strings.Cut(arg, "=")
			if optionIn("-g --glob --iglob -t --type -T --type-not", key) {
				if !attached {
					i++
					if i >= len(args) {
						return false
					}
				}
				// Match the Bash producer proof: these options only narrow
				// the listing, but do not replace its full-root scan.
				continue
			}
			if optionIn("--files -0 --null --hidden --no-ignore --no-ignore-vcs --no-ignore-parent -u -uu -uuu -L --follow", arg) {
				continue
			}
			return false
		}
		roots = append(roots, arg)
	}
	return a.listingRootsSafe(roots, cwd)
}
