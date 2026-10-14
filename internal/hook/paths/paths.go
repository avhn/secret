// Package paths classifies protected path roles by name and filesystem metadata only.
package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Resolve anchors a file operand at the effective working directory.
func Resolve(name, cwd, workdir, home string) string {
	if workdir != "" {
		if filepath.IsAbs(workdir) {
			cwd = workdir
		} else {
			cwd = filepath.Join(cwd, workdir)
		}
	}
	switch {
	case strings.HasPrefix(name, "~/"):
		name = filepath.Join(home, name[2:])
	case strings.HasPrefix(name, "$HOME/"):
		name = filepath.Join(home, name[6:])
	case strings.HasPrefix(name, "${HOME}/"):
		name = filepath.Join(home, name[8:])
	}
	if !filepath.IsAbs(name) {
		name = filepath.Join(cwd, name)
	}
	return filepath.Clean(name)
}

// Protected reports protected lexical names or symlink aliases, including dangling links.
// Unresolvable existing links are conservatively protected.
func Protected(name, cwd, workdir, home string) bool {
	p := Resolve(name, cwd, workdir, home)
	if lexical(p) {
		return true
	}
	for i := 0; i < 32; i++ {
		next, changed, uncertain := step(p)
		if uncertain {
			return true
		}
		if !changed {
			return false
		}
		p = next
		if lexical(p) {
			return true
		}
	}
	return true
}

// step resolves the first linked ancestor, preserving the remaining suffix.
func step(p string) (string, bool, bool) {
	probe := p
	for {
		info, err := os.Lstat(probe)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(probe)
			if err != nil {
				return "", false, true
			}
			if !filepath.IsAbs(link) {
				link = filepath.Join(filepath.Dir(probe), link)
			}
			suffix, err := filepath.Rel(probe, p)
			if err != nil {
				return "", false, true
			}
			return filepath.Join(link, suffix), true, false
		}
		if err != nil && !os.IsNotExist(err) {
			return "", false, true
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	return p, false, false
}

// lexical recognises store directories, credentials and protected basenames.
func lexical(p string) bool {
	p = strings.ToLower(filepath.ToSlash(p))
	base := filepath.Base(p)
	if strings.Contains(p, "/.secrets/") || strings.HasSuffix(p, "/.secrets") {
		return true
	}
	if base == ".npmrc" || base == ".pypirc" || base == ".netrc" || base == ".git-credentials" || base == ".secrets.env" {
		return true
	}
	if strings.HasSuffix(p, "/.aws/credentials") || strings.HasSuffix(p, "/.docker/config.json") || strings.HasSuffix(p, "/.config/gh/hosts.yml") {
		return true
	}
	if strings.Contains(p, "/.ssh/id_") && strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub") {
		return true
	}
	parts := strings.Split(p, "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] != "proc" {
			continue
		}
		rest := parts[i+1:]
		if len(rest) == 2 && pid(rest[0]) && rest[1] == "environ" {
			return true
		}
		if len(rest) == 4 && pid(rest[0]) && rest[1] == "task" && digits(rest[2]) && rest[3] == "environ" {
			return true
		}
	}
	if base == ".env.example" || base == ".env.sample" || base == ".env.template" || strings.HasSuffix(base, ".env.example") || strings.HasSuffix(base, ".env.sample") || strings.HasSuffix(base, ".env.template") {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".env") || strings.HasSuffix(base, ".secret")
}

// TreeProtected scans names only within a bounded search scope. An incomplete
// scan conservatively reports protected so content searches cannot proceed.
func TreeProtected(root, cwd, home string) bool {
	return TreeProtectedScope(root, cwd, home, false)
}

// TreeProtectedScope optionally includes normally ignored directories. Explicit
// roots inside ignored directories are always scanned.
func TreeProtectedScope(root, cwd, home string, includeIgnored bool) bool {
	return scanTree(root, cwd, home, includeIgnored, filepath.WalkDir, time.Now)
}

// RootProtected checks an explicit search root without reading descendants.
// A root-only proof cannot certify the filesystem root or proc trees.
func RootProtected(root, cwd, home string) bool {
	root = Resolve(root, cwd, "", home)
	if Protected(root, cwd, "", home) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return true
	}
	if resolved == string(os.PathSeparator) || resolved == "/proc" || strings.HasPrefix(resolved, "/proc/") {
		return true
	}
	info, err := os.Stat(resolved)
	return err != nil || !info.Mode().IsRegular() && !info.IsDir()
}

// treeProtected accepts a walk and clock to verify fail-closed scans under injected failures.
func treeProtected(root, cwd, home string, walk func(string, fs.WalkDirFunc) error, now func() time.Time) bool {
	return scanTree(root, cwd, home, false, walk, now)
}

func scanTree(root, cwd, home string, includeIgnored bool, walk func(string, fs.WalkDirFunc) error, now func() time.Time) bool {
	root = Resolve(root, cwd, "", home)
	if Protected(root, cwd, "", home) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return true
	}
	root = resolved
	if root == "/" || root == "/proc" || strings.HasPrefix(root, "/proc/") {
		return true
	}
	deadline := now().Add(200 * time.Millisecond)
	count := 0
	incomplete := false
	err = walk(root, func(name string, entry fs.DirEntry, walkErr error) error {
		count++
		if walkErr != nil || entry == nil || count > 4096 || now().After(deadline) {
			incomplete = true
			return os.ErrPermission
		}
		if depth := strings.Count(strings.TrimPrefix(name, root), string(os.PathSeparator)); depth > 12 {
			incomplete = true
			return os.ErrPermission
		}
		if entry.Type()&os.ModeSymlink != 0 {
			// A directory link could hide protected descendants outside this walk.
			incomplete = true
			return os.ErrPermission
		}
		if !includeIgnored && entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "node_modules") && name != root {
			return filepath.SkipDir
		}
		if Protected(name, cwd, "", home) {
			incomplete = true
			return os.ErrPermission
		}
		return nil
	})
	return incomplete || err != nil
}

// pid accepts proc's concrete and shell symbolic process selectors.
func pid(s string) bool {
	return s == "self" || s == "thread-self" || s == "$$" || s == "$ppid" || digits(s)
}

// digits checks that a process identifier is nonempty decimal text.
func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
