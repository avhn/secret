package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// ConfigWriteProtected identifies Git configuration writes, including gitfile
// worktrees and paths reached through symlinks. It never loads Git config.
func ConfigWriteProtected(name, cwd, workdir, home, xdg, global string) bool {
	if strings.HasPrefix(name, "~") && !strings.HasPrefix(name, "~/") {
		return true
	}
	if cwd == "" && !filepath.IsAbs(name) {
		return true
	}
	raw := Resolve(name, cwd, workdir, home)
	check := func(target string) bool { return gitConfigTarget(target, cwd, home, xdg, global) }
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

func gitConfigTarget(name, cwd, home, xdg, global string) bool {
	normalize := func(value string) string { return strings.ToLower(filepath.ToSlash(filepath.Clean(value))) }
	rawName, rawHome := name, home
	name, home = normalize(name), normalize(home)
	if strings.HasSuffix(name, "/.gitmodules") || strings.Contains(name, "/.git/") || strings.HasSuffix(name, "/.git") || name == home+"/.gitconfig" || strings.HasPrefix(name, home+"/.config/git/") {
		return true
	}
	if xdg != "" && strings.HasPrefix(name, normalize(filepath.Join(xdg, "git"))+"/") {
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
					if strings.HasPrefix(name, normalize(target)+"/") {
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
