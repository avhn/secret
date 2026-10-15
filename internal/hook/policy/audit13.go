package policy

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
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
		if len(args) >= 3 && args[0] == "config" && args[1] == "get" && slices.Contains(args[2:], "oauth_token") {
			return deny()
		}
	case "npm", "npx":
		if name == "npm" && len(args) > 1 && args[0] == "run" && args[1] == "env" {
			return deny()
		}
		for i, arg := range args {
			if (arg == "--call" || arg == "-c" || arg == "--c") && i+1 < len(args) && optionIn("env printenv", args[i+1]) || strings.HasPrefix(arg, "--call=") && optionIn("env printenv", strings.TrimPrefix(arg, "--call=")) || strings.HasPrefix(arg, "-c") && optionIn("env printenv", strings.TrimPrefix(arg, "-c")) {
				return deny()
			}
		}
	case "unshare", "chrt":
		for _, arg := range args {
			if optionIn("env printenv", arg) {
				return deny()
			}
		}
	case "pm2":
		if len(args) > 0 && args[0] == "env" {
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
		for i := 0; i < len(args); i++ {
			if optionIn("-C --dir --filter", args[i]) {
				i++
				continue
			}
			if strings.HasPrefix(args[i], "--dir=") || strings.HasPrefix(args[i], "--filter=") {
				continue
			}
			if args[i] == "config" && i+1 < len(args) {
				if optionIn("list ls", args[i+1]) || args[i+1] == "get" && i+2 < len(args) && credentialConfigKey(args[i+2]) {
					return deny()
				}
			}
			break
		}
	case "kubectl":
		if len(args) >= 3 && args[0] == "exec" {
			for _, v := range args[2:] {
				if optionIn("env printenv", v) {
					return deny()
				}
			}
		}
		for i, v := range args {
			if v != "get" || i+1 >= len(args) || !(optionIn("secret secrets", args[i+1]) || strings.HasPrefix(args[i+1], "secret/") || strings.HasPrefix(args[i+1], "secrets/")) {
				continue
			}
			for j, v := range args {
				output := ""
				if (v == "-o" || v == "--output") && j+1 < len(args) {
					output = args[j+1]
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
		if len(args) == 0 || !optionIn("dlx exec dotenv dotenvx", args[0]) {
			return nil, false
		}
		if optionIn("dlx exec", args[0]) {
			args = args[1:]
		}
	case "npm":
		if len(args) == 0 || args[0] != "exec" {
			return nil, false
		}
		args = args[1:]
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
	case "uvx":
		if len(args) >= 2 && args[0] == "--from" {
			args = args[2:]
		}
	case "uv", "poetry", "pipx":
		if len(args) == 0 || args[0] != "run" {
			return nil, false
		}
		args = args[1:]
	default:
		return nil, false
	}
	if name == "pipx" && len(args) >= 2 && args[0] == "--spec" {
		args = args[2:]
	}
	if len(args) == 0 {
		return nil, false
	}
	child := strings.TrimPrefix(args[0], "@dotenvx/")
	child = strings.SplitN(child, "@", 2)[0]
	if child == "python-dotenv" {
		child = "dotenv"
	}
	args[0] = child
	return args, true
}

func credentialConfigKey(key string) bool {
	key = strings.ToLower(key)
	for _, part := range []string{"auth", "token", "password", "credential"} {
		if strings.Contains(key, part) {
			return true
		}
	}
	return false
}

func (a *analyzer) rgVisibleSafe(args []string, cwd string) bool {
	for _, v := range args {
		if optionIn("--hidden --no-ignore --no-ignore-vcs -u -uu -uuu", v) || strings.HasPrefix(v, "--no-ignore") || strings.HasPrefix(v, "-g") || strings.HasPrefix(v, "--glob") || strings.HasPrefix(v, "--iglob") {
			return false
		}
	}
	roots := rgRoots(args)
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		if a.inputProtected(root, cwd) || !a.rgRootVisibleSafe(root, cwd) {
			return false
		}
	}
	return true
}

func rgRoots(args []string) []string {
	var roots []string
	pattern := true
	for i := 0; i < len(args); i++ {
		v := args[i]
		if optionIn("-e --regexp -f --file -g --glob --iglob -t --type -T --type-not -A -B -C -m --max-count --color --colors --encoding --threads --max-depth --ignore-file", v) {
			i++
			if optionIn("-e --regexp -f --file", v) {
				pattern = false
			}
			continue
		}
		if strings.HasPrefix(v, "-") {
			continue
		}
		if pattern {
			pattern = false
			continue
		}
		roots = append(roots, v)
	}
	return roots
}

func (a *analyzer) rgRootVisibleSafe(root, cwd string) bool {
	explicit := root != "."
	root = filepath.Clean(a.resolve(root, cwd))
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if resolveErr != nil {
			return false
		}
		root = resolved
	}
	// An ignored non-hidden credential file is likewise outside rg's
	// default search. Only simple, exact ignore names are certified; anything
	// ambiguous leaves the protected file in scope.
	ignored := map[string]bool{}
	if _, err := os.Stat(filepath.Join(root, ".git")); err == nil {
		if data, err := os.ReadFile(filepath.Join(root, ".gitignore")); err == nil && len(data) <= 8192 {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.ContainsAny(line, "*?[]!\\/ \t") && !strings.HasPrefix(line, "#") {
					ignored[line] = true
				}
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
			if explicit && !d.IsDir() && a.inputProtected(name, cwd) {
				return fs.ErrPermission
			}
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
