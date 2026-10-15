package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQuotedGlobEscape(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a[0]", "a0", "[abc]", "a", "foo?.ts", "foo1.ts"} {
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
	if unescapedGlob(`\[abc\]`) || !unescapedGlob(`[abc]`) {
		t.Fatal("quoted wildcard activated")
	}
}
