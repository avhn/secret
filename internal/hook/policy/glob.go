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
	// Work with native separators before removing the volume. Windows temp
	// paths can use extended-length volumes (\\?\C:), whose separator is
	// a backslash even when the shell supplies forward slashes elsewhere.
	pattern = filepath.FromSlash(pattern)
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(cwd, pattern)
	}
	// Start at the known cwd when possible. Walking from the volume root
	// can miss symlinked temp roots and needlessly enumerate a large tree.
	base := filepath.Clean(cwd)
	remainder := ""
	if rel, err := filepath.Rel(base, pattern); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		remainder = rel
	} else {
		volume := filepath.VolumeName(pattern)
		base = volume + string(os.PathSeparator)
		remainder = strings.TrimPrefix(pattern, volume)
	}
	parts := strings.Split(filepath.ToSlash(remainder), "/")
	dirs := []string{base}
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == "**" {
			next := append([]string(nil), dirs...)
			for _, dir := range dirs {
				err := filepath.WalkDir(dir, func(p string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if p != dir && entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
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
			entries, err := os.ReadDir(dir)
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			if err != nil {
				return nil, false
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") && !strings.HasPrefix(part, ".") {
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

// protectedGlob tests canonical future names even when the directory has not
// been created yet. It does not replace actual filesystem matching.
func (a *analyzer) protectedGlob(pattern, cwd string) bool {
	base := filepath.Base(pattern)
	matcher, err := globRegexp(base)
	if err != nil {
		return true
	}
	for _, name := range []string{".env", ".env.local", "app.env", "prod.secret", "id_rsa", "id_ed25519", "credentials", "config.json", "hosts.yml", ".npmrc", ".netrc", ".pypirc", ".git-credentials"} {
		if matcher.MatchString(name) && a.inputProtected(filepath.Join(filepath.Dir(pattern), name), cwd) {
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
