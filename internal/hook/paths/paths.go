// Package paths classifies protected path roles by name and filesystem metadata only.
package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// unresolved anchors path text without collapsing .. across a symlink.
func unresolved(name, cwd, workdir, home string) string {
	join := func(a, b string) string { return a + string(os.PathSeparator) + b }
	if workdir != "" {
		if filepath.IsAbs(workdir) {
			cwd = workdir
		} else {
			cwd = join(cwd, workdir)
		}
	}
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if strings.HasPrefix(name, prefix) {
			name = join(home, strings.TrimPrefix(name, prefix))
			break
		}
	}
	if !filepath.IsAbs(name) {
		name = join(cwd, name)
	}
	return name
}

// Resolve anchors a path while preserving components for physical OS lookup.
// In particular, link/.. must not be collapsed before the link is followed.
func Resolve(name, cwd, workdir, home string) string {
	return unresolved(name, cwd, workdir, home)
}

// Protected checks both lexical intent and physical component traversal. It
// reads only metadata and denies link loops and non-ENOENT resolution errors.
func Protected(name, cwd, workdir, home string) bool {
	raw := StreamBase(unresolved(name, cwd, workdir, home))
	if raw == "/proc/self/status" {
		return false
	}
	if lexical(filepath.Clean(raw)) || homeCredential(raw, home) || ConfiguredProtected(name, cwd, workdir, home, os.Getenv("KUBECONFIG")) {
		return true
	}
	resolved, err := physical(raw)
	return err != nil || lexical(resolved) || homeCredential(resolved, home)
}

// physical resolves one component at a time with a shared symlink-hop budget.
// Cleaning the full string first would turn link/../credentials into the wrong
// file when link points into a protected directory outside the lexical parent.
func physical(raw string) (string, error) {
	return physicalWith(raw, os.Lstat, os.Readlink, filepath.EvalSymlinks)
}

func physicalWith(raw string, lstat func(string) (os.FileInfo, error), readlink, canonical func(string) (string, error)) (string, error) {
	volume := filepath.VolumeName(raw)
	root := volume + string(os.PathSeparator)
	current := root
	pending := strings.Split(filepath.ToSlash(strings.TrimPrefix(raw, volume)), "/")
	hops := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			current = filepath.Dir(current)
			continue
		}
		next := filepath.Join(current, part)
		info, err := lstat(next)
		if err != nil {
			if !missingOperand(err) {
				return next, err
			}
			current = next
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			current = next
			continue
		}
		hops++
		if hops > 32 {
			return next, fs.ErrInvalid
		}
		target, err := readlink(next)
		if err != nil {
			return next, err
		}
		if filepath.IsAbs(target) {
			volume = filepath.VolumeName(target)
			current = volume + string(os.PathSeparator)
			target = strings.TrimPrefix(target, volume)
		}
		pending = append(strings.Split(filepath.ToSlash(target), "/"), pending...)
	}
	current = filepath.Clean(current)
	if runtime.GOOS == "windows" {
		// EvalSymlinks also expands 8.3 aliases on Windows. The component
		// walk above preserves link/.. semantics; canonicalize its result,
		// including the existing prefix of a not-yet-created target.
		return canonicalExisting(current, canonical)
	}
	return current, nil
}

func canonicalExisting(name string, resolve func(string) (string, error)) (string, error) {
	return canonicalPrefix(name, resolve, missingOperand)
}

// canonicalPrefix retains a resolvable ancestor when the remaining suffix cannot
// be looked up. Bound metadata work independently of path depth and spelling.
// Exhaustion remains an error for fail-closed callers.
func canonicalPrefix(name string, resolve func(string) (string, error), unresolvedError func(error) bool) (string, error) {
	tail := ""
	for candidate, count := name, 0; count < 128; count++ {
		resolved, err := resolve(candidate)
		if err == nil {
			return filepath.Join(resolved, tail), nil
		}
		parent := filepath.Dir(candidate)
		if !unresolvedError(err) || parent == candidate {
			return name, err
		}
		tail = filepath.Join(filepath.Base(candidate), tail)
		candidate = parent
	}
	return name, fs.ErrInvalid
}

// lexical recognises store directories, credentials and protected basenames.
func lexical(p string) bool {
	p = strings.ToLower(filepath.ToSlash(StreamBase(p)))
	base := filepath.Base(p)
	if ProcessAlias(p) {
		return true
	}
	if strings.Contains(p, "/.secrets/") || strings.HasSuffix(p, "/.secrets") {
		return true
	}
	if base == ".vault-token" || base == ".pgpass" || base == "application_default_credentials.json" || base == ".envrc" || base == ".npmrc" || base == ".pypirc" || base == ".netrc" || base == ".git-credentials" || base == ".secrets.env" {
		return true
	}
	if strings.HasSuffix(p, "/.kube/config") || strings.HasSuffix(p, "/.terraform.d/credentials.tfrc.json") || strings.HasSuffix(p, "/.cargo/credentials.toml") || strings.HasSuffix(p, "/.cargo/credentials") || strings.HasSuffix(p, "/.config/gcloud/credentials.db") || strings.HasSuffix(p, "/.config/gcloud/access_tokens.db") || strings.Contains(p, "/.config/gcloud/legacy_credentials/") || strings.HasSuffix(p, "/.config/gcloud/legacy_credentials") {
		return true
	}
	if strings.HasSuffix(p, "/.aws/credentials") || strings.HasSuffix(p, "/.aws/config") || strings.HasSuffix(p, "/.docker/config.json") || strings.HasSuffix(p, "/.config/gh/hosts.yml") {
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

// LexicalProtected distinguishes an explicitly protected spelling from an
// ordinary alias, for names-only tools which may return alias names.
func LexicalProtected(name, cwd, home string) bool {
	raw := filepath.Clean(unresolved(name, cwd, "", home))
	return lexical(raw) || homeCredential(raw, home) || ConfiguredProtected(name, cwd, "", home, os.Getenv("KUBECONFIG"))
}

// ProcessAlias rejects dynamic process files and directory-style descriptor aliases.
func ProcessAlias(p string) bool {
	if p == "/dev/fd" || strings.HasPrefix(p, "/dev/fd/") {
		return true
	}
	for _, prefix := range []string{"/dev/stdin/", "/dev/stdout/", "/dev/stderr/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	if p == "/proc" || strings.HasPrefix(p, "/proc/") {
		switch p {
		case "/proc/cpuinfo", "/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/version", "/proc/stat", "/proc/self/status":
			return false
		}
		return true
	}
	return false
}
