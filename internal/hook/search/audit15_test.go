package search

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit15ToolFilters(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", ".envrc", "src/a.ts"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, filter := range []struct{ glob, typ string }{{"*.ts", ""}, {"src/**/*.ts", ""}, {"*.{ts,tsx}", ""}, {"", "ts"}} {
		for _, mode := range []string{"content", "count"} {
			t.Run(filter.glob+filter.typ+mode, func(t *testing.T) {
				if got := ToolGrep(root, filter.glob, filter.typ, mode, root, root); got != "" {
					t.Fatalf("filtered public tree denied: %q", got)
				}
			})
		}
	}
	if err := os.Mkdir(filepath.Join(root, ".secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".secrets", "nested.ts"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ToolGrep(root, "*.ts", "", "content", root, root); got == "" {
		t.Fatal("filter certified a matching file inside a store")
	}
}

func TestAudit15Globstar(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		match         bool
	}{
		{"src/**/*.ts", "src/a.ts", true},
		{"src/**/*.ts", "src/unit/a.ts", true},
		{"src/**/**/**/*.ts", "src/a/b/c/a.ts", true},
		{"src/**/**/**/*.ts", "src/a/b/c/a.env", false},
	} {
		if got := globMatches(tc.pattern, tc.name, filepath.Base(tc.name)); got != tc.match {
			t.Errorf("pattern=%q name=%q match=%v", tc.pattern, tc.name, got)
		}
	}
}

func TestAudit15Selector(t *testing.T) {
	for _, tc := range []struct {
		glob      string
		protected bool
	}{
		{".env.prod*", true}, {"out/.env.staging*", true}, {".env.test?", true}, {"empty/*.secrets.env", true},
		{".envrc", true}, {".envr?", true}, {".en?.staging*", true}, {".???.production*", true}, {".en[!a].staging*", true}, {"*.ts", false}, {"src/**/*.ts", false}, {"*.{ts,tsx}", false},
	} {
		t.Run(tc.glob, func(t *testing.T) {
			if got := Selector(tc.glob); got != tc.protected {
				t.Errorf("protected=%v want=%v", got, tc.protected)
			}
		})
	}
}

func TestAudit15UnselectedSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(root, "alias.txt")); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	if got := FilteredScope(root, "*.ts", "", root, root); got != "" {
		t.Fatalf("unselected regular-file link denied: %s", got)
	}
	if err := os.Symlink(".env", filepath.Join(root, "alias.ts")); err != nil {
		t.Fatal(err)
	}
	if got := FilteredScope(root, "*.ts", "", root, root); got == "" {
		t.Fatal("selected protected-file link allowed")
	}
}
