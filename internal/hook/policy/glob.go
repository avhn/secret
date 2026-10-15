package policy

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// shellGlobMatches uses shell-style backslash escaping even on Windows, where
// filepath.Glob treats backslashes as directory separators instead of escapes.
func shellGlobMatches(pattern, cwd string, deadline time.Time) ([]string, bool) {
	if !filepath.IsAbs(pattern) {
		pattern = filepath.ToSlash(cwd) + "/" + pattern
	}
	volume := filepath.VolumeName(pattern)
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(pattern, volume), "/"), "/")
	base := volume + string(os.PathSeparator)
	if volume == "" && !strings.HasPrefix(pattern, "/") {
		base = "."
	}
	dirs := []string{base}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		var next []string
		for _, dir := range dirs {
			if time.Now().After(deadline) {
				return nil, false
			}
			entries, err := os.ReadDir(dir)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return nil, false
			}
			for _, entry := range entries {
				// Bash globs do not include hidden names unless the pattern starts with dot.
				if strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(part, ".") {
					continue
				}
				ok, err := path.Match(part, entry.Name())
				if err != nil {
					return nil, false
				}
				if ok {
					next = append(next, filepath.Join(dir, entry.Name()))
				}
				if len(next) > 200 {
					return nil, false
				}
			}
		}
		dirs = next
		if len(dirs) == 0 {
			break
		}
	}
	return dirs, true
}

func escapeGlob(value string) string {
	var b strings.Builder
	for _, r := range value {
		if strings.ContainsRune(`\*?[]`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func unescapedGlob(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			continue
		}
		if strings.ContainsRune("*?[", rune(value[i])) {
			return true
		}
	}
	return false
}
