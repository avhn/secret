package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ConfigWriteProtected identifies Git configuration writes, including gitfile
// worktrees and paths reached through symlinks. It never loads Git config.
func ConfigWriteProtected(name, cwd, workdir, home, xdg, global string) bool {
	if !ValidPath(name) || !ValidPath(cwd) || !ValidPath(workdir) || !ValidPath(home) || !ValidPath(xdg) || !ValidPath(global) {
		return true
	}
	name = nativeName(name)
	if strings.HasPrefix(name, "~") && !strings.HasPrefix(name, "~/") {
		return true
	}
	if cwd == "" && !filepath.IsAbs(name) {
		return true
	}
	raw := StreamBase(Resolve(expandXDG(name, home, xdg), cwd, workdir, home))
	if inheritedGitRootTarget(raw, cwd, workdir, home) {
		return true
	}
	check := func(target string) bool { return gitConfigTarget(target, cwd, home, xdg, global) }
	if runtime.GOOS == "windows" {
		target, err := physical(raw)
		return err != nil || nativeGitProtected(target, cwd, workdir, home) || check(raw) || check(target) || nativeConfigProtected(target, cwd, home, xdg, global)
	}
	if check(raw) {
		return true
	}
	if target, err := filepath.EvalSymlinks(raw); err == nil && check(target) {
		return true
	}
	for parent := filepath.Dir(raw); parent != filepath.Dir(parent); parent = filepath.Dir(parent) {
		target, err := filepath.EvalSymlinks(parent)
		if err == nil {
			rest, relErr := filepath.Rel(parent, raw)
			return relErr != nil || check(filepath.Join(target, rest))
		}
		if !os.IsNotExist(err) {
			return true
		}
	}
	return check(raw)
}

// Inherited roots are protected independently of Git metadata. In particular,
// an unborn legacy symbolic HEAD need not resolve to an existing regular file.
// Retain lexical intent as well as physical aliases, including missing leaves.
func inheritedGitRootTarget(name, cwd, workdir, home string) bool {
	normalize := func(value string) string { return strings.ToLower(filepath.ToSlash(filepath.Clean(value))) }
	within := func(target, root string) bool {
		target, root = normalize(target), normalize(root)
		return target == root || strings.HasPrefix(target, strings.TrimRight(root, "/")+"/")
	}
	resolved := ""
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR"} {
		value := os.Getenv(key)
		if value == "" {
			continue
		}
		root := Resolve(value, cwd, workdir, home)
		if within(name, root) {
			return true
		}
		physicalRoot, err := physical(root)
		if err != nil {
			return true
		}
		if resolved == "" {
			resolved, err = physical(name)
			if err != nil {
				return true
			}
		}
		if within(name, physicalRoot) || within(resolved, root) || within(resolved, physicalRoot) {
			return true
		}
	}
	return false
}

func gitConfigTarget(name, cwd, home, xdg, global string) bool {
	normalize := func(value string) string { return strings.ToLower(filepath.ToSlash(filepath.Clean(value))) }
	rawName, rawHome := name, home
	name, home = normalize(name), normalize(home)
	if strings.HasSuffix(name, "/.gitmodules") || strings.Contains(name, "/.git/") || strings.HasSuffix(name, "/.git") || name == home+"/.gitconfig" || name == home+"/.config/git" || strings.HasPrefix(name, home+"/.config/git/") {
		return true
	}
	if xdg != "" && (name == normalize(filepath.Join(xdg, "git")) || strings.HasPrefix(name, normalize(filepath.Join(xdg, "git"))+"/")) {
		return true
	}
	if global != "" && name == normalize(Resolve(global, cwd, "", rawHome)) {
		return true
	}
	for dir, count := filepath.Clean(cwd), 0; count < 128; dir, count = filepath.Dir(dir), count+1 {
		git := filepath.Join(dir, ".git")
		if info, err := os.Lstat(git); err == nil {
			if info.IsDir() {
				break
			}
			if info.Mode().IsRegular() && info.Size() <= 4096 {
				data, readErr := os.ReadFile(git)
				if readErr != nil {
					return true
				}
				line := strings.TrimSpace(string(data))
				if strings.HasPrefix(line, "gitdir: ") && !strings.ContainsAny(line, "\r\n\x00") {
					target := strings.TrimPrefix(line, "gitdir: ")
					if !filepath.IsAbs(target) {
						target = filepath.Join(dir, target)
					}
					if name == normalize(target) || strings.HasPrefix(name, normalize(target)+"/") {
						return true
					}
				}
			}
			break
		} else if !os.IsNotExist(err) {
			return true
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	// A separate gitdir need not have a .git component in its path.
	for dir, count := filepath.Clean(rawName), 0; dir != filepath.Dir(dir) && count < 128; dir, count = filepath.Dir(dir), count+1 {
		if info, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && info.Mode().IsRegular() {
			objects, objErr := os.Stat(filepath.Join(dir, "objects"))
			refs, refsErr := os.Stat(filepath.Join(dir, "refs"))
			if objErr == nil && refsErr == nil && objects.IsDir() && refs.IsDir() {
				return true
			}
			if _, err := os.Lstat(filepath.Join(dir, "commondir")); err == nil {
				return true
			}
		}
	}
	return false
}
