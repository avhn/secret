package policy

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/avhn/secret/internal/hook/search"
)

// Quoted metacharacters use private runes rather than backslashes: filepath
// treats a backslash as a separator on Windows, not as shell quoting.
const quotedGlobBase = 0xe000

func quotedGlob(r rune) rune {
	switch r {
	case '\\', '*', '?', '[', ']':
		return quotedGlobBase + rune(strings.IndexRune(`\*?[]`, r))
	}
	return r
}

func globRegexp(part string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(part); {
		r, size := utf8.DecodeRuneInString(part[i:])
		if r >= quotedGlobBase && r < quotedGlobBase+5 {
			b.WriteString(regexp.QuoteMeta(string(`\*?[]`[r-quotedGlobBase])))
			i += size
			continue
		}
		if size > 1 {
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
			continue
		}
		switch part[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '[':
			end := i + 1
			if end < len(part) && (part[end] == '!' || part[end] == '^') {
				end++
			}
			if end < len(part) && part[end] == ']' {
				end++
			}
			for end < len(part) {
				if part[end] == '[' && end+1 < len(part) && part[end+1] == ':' {
					if close := strings.Index(part[end+2:], ":]"); close >= 0 {
						end += close + 4
						continue
					}
				}
				if part[end] == ']' {
					break
				}
				end++
			}
			if end == len(part) {
				b.WriteString(`\[`)
				break
			}
			class := part[i : end+1]
			if len(class) > 2 && class[1] == '!' {
				class = "[^" + class[2:]
			}
			b.WriteString(class)
			i = end
		default:
			b.WriteString(regexp.QuoteMeta(part[i : i+1]))
		}
		i++
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

// shellGlobMatches never executes the shell or follows an unbounded tree.
func shellGlobMatches(pattern, cwd string, deadline time.Time) ([]string, bool) {
	return shellGlobMatchesWith(pattern, cwd, deadline, os.ReadDir)
}

func shellGlobMatchesWith(pattern, cwd string, deadline time.Time, readDir func(string) ([]os.DirEntry, error)) ([]string, bool) {
	// Work with native separators before removing the volume. Windows temp
	// paths can use extended-length volumes (\\?\C:), whose separator is
	// a backslash even when the shell supplies forward slashes elsewhere.
	pattern = filepath.FromSlash(pattern)
	if !filepath.IsAbs(pattern) {
		pattern = cwd + string(os.PathSeparator) + pattern
	}
	volume := filepath.VolumeName(pattern)
	base := volume + string(os.PathSeparator)
	remainder := strings.TrimPrefix(pattern, volume)
	// Start at the known cwd when possible. Rel cleans paths lexically, so
	// parent components (including those in cwd) must instead survive until
	// the physical directory walk below has followed their preceding symlinks.
	if !strings.Contains("/"+filepath.ToSlash(pattern)+"/", "/../") {
		if rel, err := filepath.Rel(cwd, pattern); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			base = filepath.Clean(cwd)
			remainder = rel
		}
	}
	parts := strings.Split(filepath.ToSlash(remainder), "/")
	// Resolve literal ancestors through the OS, not directory-entry regexes.
	// Windows accepts short aliases such as RUNNER~1 (and case variants) that
	// ReadDir does not return. A sibling HOME must keep that literal prefix
	// even when the cwd-relative shortcut above cannot anchor its glob.
	// Leave the final component for normal existence and dotfile checks, and
	// retain quoted metacharacters for the matcher's literal decoding.
	for len(parts) > 1 {
		if time.Now().After(deadline) {
			return nil, false
		}
		part := parts[0]
		// Resolve parents in the physical walk, not by joining text.
		if part == ".." || strings.ContainsAny(part, "*?[") || strings.IndexFunc(part, func(r rune) bool {
			return r >= quotedGlobBase && r < quotedGlobBase+5
		}) >= 0 {
			break
		}
		base = filepath.Join(base, part)
		parts = parts[1:]
	}
	dirs := []string{base}
	for index, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			var next []string
			for _, dir := range dirs {
				if time.Now().After(deadline) {
					return nil, false
				}
				resolved, err := filepath.EvalSymlinks(dir)
				if err != nil {
					return nil, false
				}
				info, err := os.Stat(resolved)
				if err != nil || !info.IsDir() {
					return nil, false
				}
				next = append(next, filepath.Dir(resolved))
			}
			dirs = next
			continue
		}
		if part == "**" {
			next := append([]string(nil), dirs...)
			for _, dir := range dirs {
				err := filepath.WalkDir(dir, func(p string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if p != dir && entry.IsDir() {
						next = append(next, p)
					}
					if len(next) > 200 || time.Now().After(deadline) {
						return fs.ErrInvalid
					}
					return nil
				})
				if err != nil {
					return nil, false
				}
			}
			dirs = next
			continue
		}
		matcher, err := globRegexp(part)
		if err != nil {
			return nil, false
		}
		var next []string
		for _, dir := range dirs {
			if time.Now().After(deadline) {
				return nil, false
			}
			entries, err := readDir(dir)
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			if err != nil {
				return nil, false
			}
			for _, entry := range entries {
				// Directory components may match hidden stores under dotglob,
				// GLOBIGNORE or a child shell's options. Retain those possible
				// matches without borrowing a default-shell option proof. Final
				// basename matching keeps its existing dotfile semantics.
				if index == len(parts)-1 && strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(part, ".") {
					continue
				}
				if matcher.MatchString(entry.Name()) {
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

// protectedGlob checks the pattern's own protected-name structure, including
// arbitrary suffixes such as .env.staging*, rather than only fixed examples.
func (a *analyzer) protectedGlob(pattern, cwd string) bool {
	if search.Selector(filepath.ToSlash(pattern)) {
		return true
	}
	// Credential basenames depend on their parent, including symlink targets.
	// Retain that context when no existing file can witness the glob match.
	pattern = filepath.FromSlash(pattern)
	base := filepath.Base(pattern)
	parent := strings.TrimSuffix(pattern, base)
	matcher, err := globRegexp(base)
	if err != nil {
		return true
	}
	for _, name := range []string{"credentials", "config.json", "hosts.yml", "id_rsa", "id_ed25519"} {
		// Keep the shell callback's slash-qualified path role on Windows too;
		// a native-only path can otherwise enter its absent bare-name exception.
		if matcher.MatchString(name) && a.inputProtected(filepath.ToSlash(parent+name), cwd) {
			return true
		}
	}
	return false
}

func escapeGlob(value string) string {
	return strings.Map(quotedGlob, value)
}

func literalGlobPattern(value string) string {
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
			b.WriteRune(quotedGlob(rune(value[i])))
		} else {
			b.WriteByte(value[i])
		}
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
