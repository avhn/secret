package policy

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

// Unresolved operands are not file reads for commands with a classified
// non-reader role. Nested substitutions are still walked independently.
func nonReaderUnknown(name string, words []*syntax.Word) bool {
	if !optionIn("docker docker-compose psql curl npm pnpm yarn bunx npx uv poetry pipx kill git", name) {
		return false
	}
	if name == "curl" {
		for _, w := range words {
			if strings.Contains(literal(w), "file://") {
				return false
			}
		}
	}
	return true
}

// A recursive grep is safe when its tree contains no protected names or its
// include selector cannot select one. Output-only modes never print content.
func recursiveGrepSafe(args []string, cwd string, a *analyzer) bool {
	recursive, names, include := false, false, ""
	var roots []string
	pattern := true
	for i := 0; i < len(args); i++ {
		v := args[i]
		if strings.HasPrefix(v, "--include=") {
			include = strings.TrimPrefix(v, "--include=")
			continue
		}
		if v == "--include" && i+1 < len(args) {
			i++
			include = args[i]
			continue
		}
		if v == "-e" || v == "--regexp" {
			i++
			pattern = false
			continue
		}
		if v == "-f" || v == "--file" {
			i++
			pattern = false
			continue
		}
		if strings.HasPrefix(v, "-") {
			if v == "--recursive" || v == "--dereference-recursive" {
				recursive = true
			}
			if v == "--files-with-matches" || v == "--files-without-match" || v == "--count" || v == "--quiet" {
				names = true
			}
			if !strings.HasPrefix(v, "--") {
				if strings.ContainsAny(v, "rR") {
					recursive = true
				}
				if strings.ContainsAny(v, "lLcq") {
					names = true
				}
			}
			continue
		}
		if pattern {
			pattern = false
			continue
		}
		roots = append(roots, v)
	}
	if !recursive {
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	if names {
		return true
	}
	follow := false
	for _, v := range args {
		if v == "--dereference-recursive" || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && strings.ContainsRune(v, 'R') {
			follow = true
		}
	}
	for _, root := range roots {
		if include != "" {
			if !a.grepIncludedSafe(root, include, cwd, follow) {
				return false
			}
		} else if a.treeProtected(root, cwd) {
			return false
		}
	}
	return true
}

func (a *analyzer) audit13Printer(name string, args []string, cwd string) bool {
	deny := func() bool { a.reason = roles.Printer; return true }
	switch name {
	case "gh":
		if len(args) >= 3 && args[0] == "config" && args[1] == "get" && args[2] == "oauth_token" {
			return deny()
		}
	case "php":
		for i, v := range args {
			if v == "-i" || v == "--info" {
				return deny()
			}
			if (v == "-r" || v == "--run") && i+1 < len(args) {
				code := args[i+1]
				if strings.Contains(code, "phpinfo(") || (strings.Contains(code, "print_r(") || strings.Contains(code, "var_dump(")) && (strings.Contains(code, "$_SERVER") || strings.Contains(code, "$_ENV") || strings.Contains(code, "getenv(")) {
					return deny()
				}
			}
		}
	case "pnpm", "yarn":
		if len(args) >= 2 && args[0] == "config" && (args[1] == "list" || args[1] == "get") {
			return deny()
		}
	case "kubectl":
		if len(args) >= 3 && args[0] == "get" && (args[1] == "secret" || args[1] == "secrets") {
			for i, v := range args[2:] {
				output := ""
				if (v == "-o" || v == "--output") && i+3 < len(args) {
					output = args[i+3]
				}
				if strings.HasPrefix(v, "-o=") || strings.HasPrefix(v, "--output=") {
					_, output, _ = strings.Cut(v, "=")
				}
				if strings.HasPrefix(v, "-o") && len(v) > 2 && !strings.HasPrefix(v, "--") {
					output = v[2:]
				}
				if optionIn("yaml json jsonpath go-template", strings.SplitN(output, "=", 2)[0]) {
					return deny()
				}
			}
		}
	case "zip":
		if len(args) > 1 && args[0] == "-" {
			for _, v := range args[1:] {
				if a.inputProtected(v, cwd) {
					a.reason = roles.FileInput
					return true
				}
			}
		}
	}
	return false
}

func safePackageChild(name string, args []string) ([]string, bool) {
	switch name {
	case "npx", "bunx":
		for len(args) > 0 && strings.HasPrefix(args[0], "-") {
			if args[0] == "--" {
				args = args[1:]
				break
			}
			args = args[1:]
		}
	case "pnpm", "yarn":
		if len(args) == 0 || !optionIn("dlx exec", args[0]) {
			return nil, false
		}
		args = args[1:]
	case "uv", "poetry", "pipx":
		if len(args) == 0 || args[0] != "run" {
			return nil, false
		}
		args = args[1:]
	default:
		return nil, false
	}
	if len(args) == 0 {
		return nil, false
	}
	return args, true
}

func (a *analyzer) rgVisibleSafe(args []string, cwd string) bool {
	for _, v := range args {
		if optionIn("--hidden --no-ignore --no-ignore-vcs -u -uu -uuu", v) || strings.HasPrefix(v, "--no-ignore") || strings.HasPrefix(v, "-g") || strings.HasPrefix(v, "--glob") || strings.HasPrefix(v, "--iglob") {
			return false
		}
	}
	root := cwd
	// A default search excludes dotfiles and ignored build trees.
	if len(args) > 0 {
		last := args[len(args)-1]
		if last == "." || last == "src" {
			root = filepath.Join(cwd, last)
		}
	}
	// An ignored non-hidden credential file is likewise outside rg's
	// default search. Only simple, exact ignore names are certified; anything
	// ambiguous leaves the protected file in scope.
	ignored := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(root, ".gitignore")); err == nil && len(data) <= 8192 {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.ContainsAny(line, "*?[]!\\/ \t") && !strings.HasPrefix(line, "#") {
				ignored[line] = true
			}
		}
	}
	count := 0
	err := filepath.WalkDir(root, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		count++
		if count > 4096 {
			return fs.ErrInvalid
		}
		if name == root {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ignored[d.Name()] && filepath.Dir(name) == root {
			return nil
		}
		if a.inputProtected(name, cwd) {
			return fs.ErrPermission
		}
		return nil
	})
	return err == nil
}

func dockerPIDPipe(upstream, downstream *syntax.Stmt) bool {
	x, ok := upstream.Cmd.(*syntax.CallExpr)
	if !ok || len(x.Args) != 3 || literal(x.Args[0]) != "docker" || literal(x.Args[1]) != "ps" || literal(x.Args[2]) != "-q" {
		return false
	}
	y, ok := downstream.Cmd.(*syntax.CallExpr)
	if !ok || len(y.Args) != 3 {
		return false
	}
	return literal(y.Args[0]) == "xargs" && literal(y.Args[1]) == "docker" && literal(y.Args[2]) == "stop"
}

// An include filter certifies only matching files; unknown traversal fails
// closed. The scan is bounded like other filesystem-scope checks.
func (a *analyzer) grepIncludedSafe(root, selector, cwd string, follow bool) bool {
	if a.inputProtected(root, cwd) {
		return false
	}
	directory := a.resolve(root, cwd)
	count := 0
	err := filepath.WalkDir(directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry == nil || time.Now().After(a.deadline) {
			return fs.ErrInvalid
		}
		count++
		if count > 4096 {
			return fs.ErrInvalid
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if follow {
				return fs.ErrInvalid
			}
			return nil // grep -r does not follow encountered symlinks.
		}
		if entry.IsDir() {
			return nil
		}
		matched, matchErr := path.Match(selector, entry.Name())
		if matchErr != nil {
			return fs.ErrInvalid
		}
		if matched && a.inputProtected(name, cwd) {
			return fs.ErrPermission
		}
		return nil
	})
	return err == nil
}
