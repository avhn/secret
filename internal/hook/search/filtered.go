package search

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
)

// FilteredScope checks matching names only, never file values. Symlinks and
// incomplete walks cannot certify a content search outside protected stores.
func FilteredScope(root, glob, typ, cwd, home string) string {
	if glob == "" {
		glob = typeGlob(typ)
	}
	if !CanNarrow(glob) || strings.Count(glob, "**") > 3 || len(glob) > 1024 {
		return ScopeReason
	}
	root = paths.Resolve(root, cwd, "", home)
	if dir, ok := globDirectory(glob); ok {
		if paths.TreeProtectedScope(filepath.Join(root, filepath.FromSlash(dir)), cwd, home, true) {
			return ScopeReason
		}
		return ""
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ScopeReason
	}
	root = resolved
	deadline := time.Now().Add(200 * time.Millisecond)
	count := 0
	err = filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		count++
		if walkErr != nil || entry == nil || count > 4096 || time.Now().After(deadline) {
			return fs.ErrInvalid
		}
		relative, relErr := filepath.Rel(root, name)
		if relErr != nil {
			return relErr
		}
		selected := globMatches(strings.ToLower(glob), strings.ToLower(filepath.ToSlash(relative)), strings.ToLower(entry.Name()))
		if entry.Type()&os.ModeSymlink != 0 {
			info, err := os.Stat(name)
			if err != nil || !info.Mode().IsRegular() {
				return fs.ErrInvalid
			}
			if selected && paths.Protected(name, cwd, "", home) {
				return fs.ErrPermission
			}
			return nil
		}
		if entry.IsDir() {
			if name != root && globMatches(strings.ToLower(glob), "", strings.ToLower(entry.Name())) {
				return fs.ErrInvalid
			}
			return nil
		}
		if selected && paths.Protected(name, cwd, "", home) {
			return fs.ErrPermission
		}
		return nil
	})
	if err != nil {
		return ScopeReason
	}
	return ""
}

func typeGlob(typ string) string {
	switch strings.ToLower(typ) {
	case "ts", "typescript":
		return "*.{ts,tsx,mts,cts}"
	case "js", "javascript":
		return "*.{js,jsx,mjs,cjs}"
	case "go":
		return "*.go"
	case "rust":
		return "*.rs"
	case "py", "python":
		return "*.py"
	case "md", "markdown":
		return "*.{md,markdown,mdown,mkd,mkdn,mdwn}"
	}
	return ""
}

// CanNarrow rejects negative alternatives before considering protected names.
// A literal DIR/** instead narrows by its directory, whose whole tree is checked.
func CanNarrow(glob string) bool {
	_, directory := globDirectory(glob)
	return positiveGlob(glob) && (directory || !Selector(glob))
}

// NegativeGlob reports a selector consisting only of exclusions. It cannot
// enlarge rg's default visible scope, but provides no narrower-scope proof.
func NegativeGlob(glob string) bool {
	if glob == "" || len(glob) > 4096 {
		return false
	}
	variants, ok := selectorBraces(glob, 64)
	if !ok {
		return false
	}
	for _, variant := range variants {
		if !strings.HasPrefix(variant, "!") {
			return false
		}
	}
	return true
}

func positiveGlob(glob string) bool {
	if glob == "" || len(glob) > 4096 {
		return false
	}
	variants, ok := selectorBraces(glob, 64)
	if !ok {
		return false
	}
	for _, variant := range variants {
		if strings.HasPrefix(variant, "!") {
			return false
		}
	}
	return true
}

func globDirectory(glob string) (string, bool) {
	dir, ok := strings.CutSuffix(glob, "/**")
	return dir, ok && dir != "" && !strings.ContainsAny(dir, "*?[]{}!\\")
}

func globMatches(glob, relative, base string) bool {
	glob = strings.ReplaceAll(glob, "[!", "[^")
	variants, ok := selectorBraces(glob, 64)
	if !ok {
		return true
	}
	for _, pattern := range variants {
		if !strings.Contains(pattern, "/") {
			if match, _ := path.Match(pattern, base); match {
				return true
			}
			continue
		}
		if pathGlobMatch(strings.Split(pattern, "/"), strings.Split(relative, "/")) {
			return true
		}
	}
	return false
}

func pathGlobMatch(pattern, name []string) bool {
	// Dynamic programming avoids exponential alternatives from multiple **
	// components while retaining zero-directory globstar matches.
	matched := make([]bool, len(name)+1)
	matched[0] = true
	for _, component := range pattern {
		next := make([]bool, len(name)+1)
		if component == "**" {
			next[0] = matched[0]
			for j := 1; j <= len(name); j++ {
				next[j] = matched[j] || next[j-1]
			}
		} else {
			for j := 1; j <= len(name); j++ {
				match, err := path.Match(component, name[j-1])
				next[j] = matched[j-1] && err == nil && match
			}
		}
		matched = next
	}
	return matched[len(name)]
}
