package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
			t.Errorf("%q: matches=%q ok=%v", pattern, got, ok)
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
		t.Fatalf("volume-like path: matches=%q ok=%v", got, ok)
	}
}
