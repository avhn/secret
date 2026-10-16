package policy

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"github.com/avhn/secret/internal/hook/search"
	"mvdan.cc/sh/v3/syntax"
)

// Unresolved operands are not file reads for commands with a classified
// non-reader role. Nested substitutions are still walked independently.
func (a *analyzer) nonReaderUnknown(name string, operands []expandedOperand, cwd string) bool {
	if !optionIn("docker docker-compose psql curl npm pnpm yarn bunx npx uv poetry pipx kill git", name) {
		return false
	}
	if (name == "docker" || name == "docker-compose") && uncertainDockerMount(operands, cwd != "" && !strings.Contains(a.source, "PWD=") && !a.inputProtected(cwd, cwd)) {
		return false
	}
	if name == "curl" {
		for _, operand := range operands {
			if strings.Contains(a.raw(operand.source), "file://") {
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
	case "npm", "npx":
		if name == "npm" && len(args) > 1 && args[0] == "run" && args[1] == "env" {
			return deny()
		}
		for i, arg := range args {
			if (arg == "--call" || arg == "-c" || arg == "--c") && i+1 < len(args) && optionIn("env printenv", args[i+1]) || strings.HasPrefix(arg, "--call=") && optionIn("env printenv", strings.TrimPrefix(arg, "--call=")) || strings.HasPrefix(arg, "-c") && optionIn("env printenv", strings.TrimPrefix(arg, "-c")) {
				return deny()
			}
		}
	case "unshare":
		for _, arg := range args {
			if optionIn("env printenv", arg) {
				return deny()
			}
		}
	case "pm2":
		if len(args) > 0 && args[0] == "env" {
			return deny()
		}
	case "kubectl":
		if len(args) >= 3 && args[0] == "exec" {
			for _, v := range args[2:] {
				if optionIn("env printenv", v) {
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
	// Call values are shell programs, not executable names. Leave them for
	// commandSlot instead of hiding them behind a peeled package child.
	if optionIn("npx npm pnpm yarn", name) {
		for _, arg := range args {
			if packageCallOption(arg) {
				return nil, false
			}
		}
		if leading := packageLeadingOptions(args); name == "yarn" && len(leading) > 0 && leading[0] == "exec" {
			return nil, false
		}
	}
	switch name {
	case "npx", "bunx":
		args = packageRunnerOptions(args)
	case "pnpm", "yarn":
		args = packageLeadingOptions(args)
		if len(args) == 0 || args[0] == "config" {
			return nil, false
		}
		if optionIn("dlx exec run", args[0]) {
			args = packageRunnerOptions(args[1:])
		}
	case "python", "python3":
		if len(args) < 2 || args[0] != "-m" {
			return nil, false
		}
		args = args[1:]
	case "npm":
		if len(args) == 0 || !optionIn("exec x", args[0]) {
			return nil, false
		}
		args = args[1:]
		for len(args) > 0 {
			if args[0] == "--" {
				args = args[1:]
				break
			}
			if optionIn("-y --yes", args[0]) || strings.HasPrefix(args[0], "--yes=") || strings.HasPrefix(args[0], "--package=") {
				args = args[1:]
				continue
			}
			if optionIn("-p --package", args[0]) && len(args) >= 2 {
				args = args[2:]
				continue
			}
			break
		}
		// npm's separator belongs to npm, not the selected local binary.
		args = append([]string(nil), args...)
		for i, arg := range args {
			if arg == "--" {
				args = append(args[:i], args[i+1:]...)
				break
			}
		}
	case "uvx":
		if len(args) >= 2 && args[0] == "--from" {
			args = args[2:]
		}
		if len(args) > 0 && strings.HasPrefix(args[0], "--from=") {
			args = args[1:]
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
	if name == "pipx" && len(args) > 0 && strings.HasPrefix(args[0], "--spec=") {
		args = args[1:]
	}
	if len(args) == 0 {
		return nil, false
	}
	child := strings.TrimPrefix(args[0], "@dotenvx/")
	child = strings.SplitN(child, "@", 2)[0]
	if child == "python-dotenv" {
		child = "dotenv"
	}
	args = append([]string(nil), args...)
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
	status, hidden := search.Config(os.Getenv("RIPGREP_CONFIG_PATH"), cwd, a.home)
	if status == 2 || a.configUntrusted {
		return false
	}
	for i := 0; i < len(args); i++ {
		v := args[i]
		if v == "--hidden" {
			hidden = true
			continue
		}
		if optionIn("-g --glob --iglob", v) {
			i++
			if i >= len(args) || !search.NegativeGlob(args[i]) {
				return false
			}
			continue
		}
		if strings.HasPrefix(v, "--glob=") || strings.HasPrefix(v, "--iglob=") || strings.HasPrefix(v, "-g") && len(v) > 2 {
			g := strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(v, "--glob="), "--iglob="), "-g")
			if !search.NegativeGlob(g) {
				return false
			}
			continue
		}
		if optionIn("--no-ignore --no-ignore-vcs -u -uu -uuu", v) || strings.HasPrefix(v, "--no-ignore") {
			return false
		}
	}
	roots := rgRoots(args)
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		if a.inputProtected(root, cwd) || !a.visibleRootSafe(root, cwd, !hidden, false) {
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
	return a.visibleRootSafe(root, cwd, true, false)
}

func (a *analyzer) visibleRootSafe(root, cwd string, skipHidden, gitSearch bool) bool {
	explicit := root != "."
	root = filepath.Clean(a.resolve(root, cwd))
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, resolveErr := filepath.EvalSymlinks(root)
		if resolveErr != nil {
			return false
		}
		root = resolved
	}
	if !gitSearch {
		for dir, count := root, 0; ; dir, count = filepath.Dir(dir), count+1 {
			// Ripgrep's higher-priority ignore files above a work tree can
			// restore ignored credentials too. Exhausting the bound is not
			// a proof that those ancestors are safe.
			if count >= 128 || rgIgnoreOverride(dir) {
				return false
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	// An ignored non-hidden credential file is likewise outside rg's
	// default search. Only simple root-name ignore patterns are certified;
	// anything ambiguous leaves the protected file in scope.
	ignored := []string{}
	ignorePath := filepath.Join(root, ".gitignore")
	if resolveGitDirectory(root, "") != "" && !a.inputProtected(ignorePath, cwd) {
		if info, err := os.Stat(ignorePath); err == nil && info.Mode().IsRegular() && info.Size() <= 8192 {
			if data, err := os.ReadFile(ignorePath); err == nil && len(data) <= 8192 {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					// Negations can restore an earlier excluded credential file.
					// Leave those scopes uncertified rather than drop the rule.
					if strings.HasPrefix(line, "!") {
						ignored = nil
						break
					}
					if line != "" && !strings.ContainsAny(line, "!\\/ \t") && !strings.HasPrefix(line, "#") {
						ignored = append(ignored, line)
					}
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
		if skipHidden && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") || gitSearch && d.Name() == ".git" {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if !gitSearch && rgIgnoreOverride(name) {
				return fs.ErrInvalid
			}
			if _, err := os.Lstat(filepath.Join(name, ".gitignore")); name != root && (err == nil || !os.IsNotExist(err)) {
				return fs.ErrInvalid
			}
		}
		// Slash-free Git ignore patterns also apply in descendant directories.
		for _, pattern := range ignored {
			if matched, err := path.Match(pattern, d.Name()); err == nil && matched {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if a.inputProtected(name, cwd) {
			return fs.ErrPermission
		}
		return nil
	})
	return err == nil
}

// Higher-priority ripgrep ignore files can unignore credentials. Their contents
// are not part of the simple Git-ignore proof; errors also refuse certification.
func rgIgnoreOverride(dir string) bool {
	for _, name := range []string{".ignore", ".rgignore"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil || !os.IsNotExist(err) {
			return true
		}
	}
	return false
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
