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
		if runtime.GOOS == "windows" && strings.ContainsAny(tc.want[0], "[]?") {
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
