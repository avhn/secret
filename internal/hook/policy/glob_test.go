package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestQuotedGlobEscape(t *testing.T) {
	root := t.TempDir()
	names := []string{"a0", "a", "foo1.ts"}
	if runtime.GOOS != "windows" {
		names = append(names, "a[0]", "[abc]", "foo?.ts")
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		pattern string
		want    []string
	}{
		{escapeGlob("[abc]"), []string{"[abc]"}},
		{"a" + escapeGlob("[0]"), []string{"a[0]"}},
		{"foo" + escapeGlob("?") + ".ts", []string{"foo?.ts"}},
		{"foo?.ts", []string{"foo1.ts", "foo?.ts"}},
	} {
		if runtime.GOOS == "windows" && (strings.ContainsAny(tc.want[0], "[]?") || tc.pattern == "foo?.ts") {
			continue
		}
		got, ok := shellGlobMatches(tc.pattern, root, time.Now().Add(time.Second))
		if !ok || len(got) != len(tc.want) {
			globFailure(t, tc.pattern, root)
			t.Fatalf("%q: paths=%q valid=%v, want=%q", tc.pattern, got, ok, tc.want)
		}
		for i, name := range tc.want {
			if filepath.Base(got[i]) != name {
				t.Fatalf("%q: got %q want %q", tc.pattern, got[i], name)
			}
		}
	}
	if filepath.Base(filepath.Join(root, escapeGlob("*"))) != escapeGlob("*") {
		t.Fatal("quoted wildcard changed into a path separator")
	}
	if unescapedGlob(`\[abc\]`) || !unescapedGlob(`[abc]`) {
		t.Fatal("quoted wildcard activated")
	}
}

// Native joins exercise the absolute and volume-bearing path split, not only
// the relative shell spelling accepted by the matcher.
func globFailure(t *testing.T, pattern, cwd string) {
	t.Helper()
	abs := filepath.FromSlash(pattern)
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(cwd, abs)
	}
	base := filepath.Clean(cwd)
	if rel, err := filepath.Rel(base, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		abs = rel
	} else {
		base = filepath.VolumeName(abs) + string(os.PathSeparator)
		abs = strings.TrimPrefix(abs, filepath.VolumeName(abs))
	}
	parts := strings.Split(filepath.ToSlash(abs), "/")
	t.Logf("glob pattern=%q cwd=%q base=%q components=%q", pattern, cwd, base, parts)
	for _, dir := range []string{base, cwd, filepath.Dir(filepath.Join(cwd, pattern))} {
		entries, err := os.ReadDir(dir)
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Logf("glob directory=%q entries=%q err=%v", dir, names, err)
	}
}

func TestGlobNativeRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "packages", "unit"), 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, "packages", "unit", "package.json")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{filepath.Join(root, "packages", "*", "package.json"), filepath.ToSlash(filepath.Join(root, "packages", "*", "package.json"))} {
		got, ok := shellGlobMatches(pattern, root, time.Now().Add(time.Second))
		if !ok || len(got) != 1 || got[0] != name {
			globFailure(t, pattern, root)
			t.Errorf("%q: matches=%q ok=%v", pattern, got, ok)
		}
	}
}

func TestGlobProtectedNativeNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{".env", "app.env"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ pattern, want string }{{".env*", ".env"}, {"app.*", "app.env"}, {filepath.Join(root, "*.env"), "app.env"}} {
		got, ok := shellGlobMatches(tc.pattern, root, time.Now().Add(time.Second))
		found := false
		for _, path := range got {
			if filepath.Base(path) == tc.want {
				found = true
			}
		}
		if !ok || !found {
			globFailure(t, tc.pattern, root)
			t.Errorf("pattern=%q matches=%q valid=%v missing %q", tc.pattern, got, ok, tc.want)
		}
	}
}

func TestGlobSymlinkedTempRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	actual := t.TempDir()
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, ".env"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{".env*", filepath.Join(link, ".env*")} {
		got, ok := shellGlobMatches(pattern, link, time.Now().Add(time.Second))
		if !ok || len(got) != 1 || filepath.Base(got[0]) != ".env" {
			globFailure(t, pattern, link)
			t.Fatalf("pattern=%q matches=%q ok=%v", pattern, got, ok)
		}
	}
}

// Missing credential names still have protected parent context. The callback
// mirrors the shell adapter's bare-operand exception on every native platform.
func TestProtectedGlobMissingCredentialContext(t *testing.T) {
	root := t.TempDir()
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", root)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", root)
	}
	a := &analyzer{home: root, protected: check}
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{".docker/c*.json", true}, {".aws/cred*", true}, {".config/gh/h*.yml", true},
		{"public/c*.json", false}, {".docker/*.ts", false}, {".docker/[", true},
	} {
		native := filepath.Join(root, filepath.FromSlash(tc.pattern))
		for _, pattern := range []string{native, filepath.ToSlash(native)} {
			t.Run(pattern, func(t *testing.T) {
				if got := a.protectedGlob(pattern, root); got != tc.want {
					t.Errorf("protected=%v want %v", got, tc.want)
				}
			})
		}
	}
}

func TestGlobVolumeLikeComponent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("colon is a native Windows volume separator")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "C:", "code")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "main.ts")
	if err := os.WriteFile(name, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got, ok := shellGlobMatches(filepath.Join(root, "C:", "*", "*.ts"), root, time.Now().Add(time.Second))
	if !ok || len(got) != 1 || got[0] != name {
		globFailure(t, filepath.Join(root, "C:", "*", "*.ts"), root)
		t.Fatalf("volume-like path: matches=%q ok=%v", got, ok)
	}
}
