package policy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
)

// Package execution options belong to the launcher only until its child starts.
// Keep directory alternatives local to that child, never the following statement.
type packageExecOptions struct {
	cwd        string
	base       string
	baseSet    bool
	workspaces []string
	shell      bool
	prefix     bool
	bad        bool
	root       bool
}

func (a *analyzer) packageExecOptions(name string, args []string, options *packageExecOptions) []string {
	if !options.baseSet {
		options.base, options.baseSet = options.cwd, true
	}
	for len(args) > 0 {
		arg := args[0]
		key, value, attached := strings.Cut(arg, "=")
		kind := ""
		switch {
		case name == "npm" && key == "--prefix", name != "npm" && optionIn("-C --dir", key), name == "yarn" && key == "--cwd":
			kind = "directory"
		case name == "npm" && optionIn("-w --workspace", key), name == "pnpm" && optionIn("-F --filter", key):
			kind = "workspace"
		case name == "npm" && optionIn("--loglevel -p --package", key):
			kind = "value"
		case name != "npm" && strings.HasPrefix(arg, "-C") && len(arg) > 2:
			kind, value, attached = "directory", arg[2:], true
		case name == "npm" && strings.HasPrefix(arg, "-w") && arg != "-ws" && len(arg) > 2,
			name == "pnpm" && strings.HasPrefix(arg, "-F") && len(arg) > 2:
			kind, value, attached = "workspace", arg[2:], true
		case name == "pnpm" && optionIn("-c --shell-mode", arg):
			options.shell = true
		case name == "npm" && optionIn("-ws --workspaces", key), name == "pnpm" && optionIn("-r --recursive", key):
			options.workspaces = append(options.workspaces, "")
		case name == "pnpm" && optionIn("-w --workspace-root", key):
			options.root = true
		case optionIn("-s --silent -q --quiet -y --yes --if-present", key),
			name == "npm" && optionIn("-g --global", key),
			name == "yarn" && optionIn("-w --workspace-root", key):
		default:
			return args
		}
		args = args[1:]
		if kind == "" {
			continue
		}
		if !attached {
			if len(args) == 0 {
				options.bad = true
				return nil
			}
			value, args = args[0], args[1:]
		}
		switch kind {
		case "directory":
			options.cwd = a.resolve(value, options.base)
			options.prefix = name == "npm"
		case "workspace":
			options.workspaces = append(options.workspaces, value)
		}
	}
	return args
}

func (a *analyzer) packageExec(name string, args []string, depth int, cwd string, direct bool) bool {
	if !optionIn("npm pnpm yarn", name) {
		return false
	}
	options := packageExecOptions{cwd: cwd}
	leading := a.packageExecOptions(name, args, &options)
	if len(leading) == 0 {
		return false
	}
	var child []string
	fallback := false
	switch {
	case name == "npm" && optionIn("exec x", leading[0]):
		child = a.npmExecArguments(leading[1:], &options)
	case leading[0] == "exec":
		child = a.packageExecOptions(name, leading[1:], &options)
	case name == "pnpm" && !optionIn("config run dlx", leading[0]):
		// pnpm falls back to exec for local binaries, including shell mode.
		child, fallback = leading, true
	default:
		return false
	}
	if name != "npm" && len(child) > 0 && child[0] == "--" {
		child = child[1:]
	}
	if options.root {
		options.cwd = a.packageWorkspaceRoot(options.cwd)
	}
	if options.bad || len(child) == 0 {
		a.reason = roles.Indeterminate
		return true
	}
	// Operand-free pnpm script fallbacks do not need a workspace path proof.
	// Still classify the child so env and other default token printers deny.
	if fallback && len(child) == 1 && !options.shell {
		a.command(child, depth+1, options.cwd, direct)
		return true
	}
	dirs := []string{options.cwd}
	if options.prefix || len(options.workspaces) > 0 {
		dirs = a.cwdUnion(dirs, []string{cwd})
	}
	unresolved := false
	for _, selector := range options.workspaces {
		dir := ""
		if selector != "" && !strings.ContainsAny(selector, "*?[]{}$`!") && options.cwd != "" {
			resolved := a.resolve(selector, options.cwd)
			pathSelector := name != "pnpm" || strings.HasPrefix(selector, "./") || strings.HasPrefix(selector, "../") || filepath.IsAbs(selector)
			if name == "npm" {
				info, err := os.Stat(filepath.Join(resolved, "package.json"))
				pathSelector = err == nil && info.Mode().IsRegular()
			}
			if info, err := os.Stat(resolved); pathSelector && err == nil && info.IsDir() {
				dir = resolved
			}
		}
		if dir == "" {
			unresolved = true
		} else {
			dirs = a.cwdUnion(dirs, []string{dir})
		}
	}
	if unresolved {
		dirs = a.cwdUnion(dirs, a.packageWorkspaceDirectories(options.cwd))
	}
	for _, dir := range dirs {
		if name == "yarn" || options.shell {
			a.strictCommandSlot(name, strings.Join(child, " "), depth, dir)
		} else {
			normalized := append([]string{"exec"}, child...)
			if !a.commandSlot(name, normalized, depth, dir) {
				if words, ok := safePackageChild(name, normalized); ok {
					a.command(words, depth+1, dir, direct)
				} else {
					a.reason = roles.Indeterminate
				}
			}
		}
		if a.reason != "" {
			break
		}
	}
	return true
}

// Names and filter expressions may select any project workspace. Enumerate
// directory metadata only, with the ordinary cwd/entry/deadline bounds. Git
// internals and installed dependencies are not workspace candidates; explicit
// path selectors above still check them. An uncertifiable walk cannot allow.
func (a *analyzer) packageWorkspaceDirectories(root string) []string {
	root = a.packageWorkspaceRoot(root)
	if a.reason != "" {
		return nil
	}
	if root == "" {
		return []string{""}
	}
	return a.packageWorkspaceTree(root)
}

func (a *analyzer) packageWorkspaceRoot(root string) string {
	if root == "" {
		return ""
	}
	physical, err := filepath.EvalSymlinks(root)
	if err != nil {
		a.reason = roles.Indeterminate
		return ""
	}
	root = physical
	// Package managers locate workspace roots above a selected subdirectory.
	// Inspect marker existence only, never manifest contents or Git config.
	for dir, count := root, 0; ; dir, count = filepath.Dir(dir), count+1 {
		if count >= 128 || time.Now().After(a.deadline) {
			a.reason = roles.Indeterminate
			return ""
		}
		for _, marker := range []string{"package.json", "pnpm-workspace.yaml", ".git"} {
			if _, err := os.Lstat(filepath.Join(dir, marker)); err == nil {
				root = dir
				if marker == ".git" {
					return root
				}
			} else if !os.IsNotExist(err) {
				a.reason = roles.Indeterminate
				return ""
			}
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return root
}

func (a *analyzer) packageWorkspaceTree(root string) []string {
	var dirs []string
	entries := 0
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		entries++
		if err != nil || entries > 4096 || time.Now().After(a.deadline) {
			return fs.ErrInvalid
		}
		if name != root && (entry.Name() == ".git" || entry.Name() == "node_modules") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			info, err := os.Stat(name)
			if err != nil || info.IsDir() {
				return fs.ErrInvalid
			}
		}
		if entry.IsDir() {
			dirs = a.cwdUnion(dirs, []string{name})
			if a.reason != "" {
				return fs.ErrInvalid
			}
		}
		return nil
	})
	if err != nil {
		a.reason = roles.Indeterminate
		return nil
	}
	return dirs
}

// Unlike pnpm and npx, npm parses its own options after positional arguments
// too. Only the first -- ends that grammar and gives the child its own options.
func (a *analyzer) npmExecArguments(args []string, options *packageExecOptions) []string {
	var child []string
	for len(args) > 0 {
		if args[0] == "--" {
			return append(child, args[1:]...)
		}
		remaining := a.packageExecOptions("npm", args, options)
		if len(remaining) < len(args) {
			args = remaining
			continue
		}
		child = append(child, args[0])
		if optionIn("-c --call --c", args[0]) && len(args) > 1 {
			child = append(child, args[1])
			args = args[2:]
		} else {
			args = args[1:]
		}
	}
	return child
}
