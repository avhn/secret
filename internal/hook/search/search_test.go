package search

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfig(t *testing.T) {
	root := t.TempDir()
	home := root
	file := filepath.Join(root, "synthetic-rg-config")
	base := "--hidden\n"
	for _, v := range required {
		base += "--iglob=!" + v + "\n"
	}
	for _, tc := range []struct {
		name, extra string
		status      int
	}{
		{"certified", "", 0}, {"display", "--smart-case\n--max-columns=120\n", 0},
		{"positive glob", "--glob=.env\n", 2}, {"follow", "--follow\n", 2},
		{"no ignore", "--no-ignore-vcs\n", 2}, {"zip", "--search-zip\n", 2},
		{"preprocess", "--pre=cat\n", 2}, {"nul", string([]byte{0}), 2},
		{"partial", strings.Replace(base, "--iglob=!.env\n", "", 1), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := base + tc.extra
			if tc.name == "partial" {
				data = tc.extra
			}
			if err := os.WriteFile(file, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			got, _ := Config(file, root, home)
			if got != tc.status {
				t.Fatalf("status %d, want %d", got, tc.status)
			}
		})
	}
	t.Run("directory", func(t *testing.T) {
		status, _ := Config(root, root, home)
		if status != 2 {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		if err := os.WriteFile(file, []byte(strings.Repeat("a", 8193)), 0600); err != nil {
			t.Fatal(err)
		}
		status, _ := Config(file, root, home)
		if status != 2 {
			t.Fatalf("status %d", status)
		}
	})
}
func TestScope(t *testing.T) {
	root := t.TempDir()
	home := root
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "synthetic-config")
	base := ""
	for _, v := range required {
		base += "--iglob=!" + v + "\n"
	}
	if err := os.WriteFile(config, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		words  []string
		config string
		deny   bool
	}{
		{"certified", []string{"rg", "TOKEN", "."}, config, false},
		{"explicit", []string{"rg", "TOKEN", "src/.env"}, config, true},
		{"uncertified", []string{"rg", "TOKEN", "."}, "", true},
		{"names", []string{"rg", "-l", "TOKEN", "."}, "", false},
		{"git", []string{"git", "grep", "TOKEN", "--", "src"}, config, true},
		{"git names", []string{"git", "grep", "-l", "TOKEN", "--", "src"}, config, false},
		{"hidden", []string{"rg", "--hidden", "TOKEN", "src"}, config, false},
		{"positive", []string{"rg", "-g.env", "TOKEN", "src"}, config, true},
		{"pattern file", []string{"rg", "-f", "src/.env", "TOKEN", "src"}, config, true},
		{"missing pattern file names", []string{"rg", "-l", "-f", "missing-pattern", "src"}, config, true},
		{"missing attached pattern file names", []string{"rg", "-l", "--file=missing-pattern", "src"}, config, true},
		{"pattern file directory names", []string{"rg", "-l", "-f", "src", "TOKEN"}, config, false},
		{"follow", []string{"rg", "--follow", "TOKEN", "src"}, config, true},
		{"unrestricted", []string{"rg", "-uu", "TOKEN", "src"}, config, true},
		{"zip", []string{"rg", "--search-zip", "TOKEN", "src"}, config, true},
		{"preprocessor", []string{"rg", "--pre=cat", "TOKEN", "src"}, config, true},
		{"git option", []string{"git", "grep", "--no-index", "TOKEN", "--", "src"}, config, true}} {
		t.Run(tc.name, func(t *testing.T) {
			got := Scope(tc.words, root, home, tc.config, false)
			if (got != "") != tc.deny {
				t.Fatalf("reason %q, deny %t", got, tc.deny)
			}
		})
	}
}
func TestCertifiedExplicitIgnoredRoot(t *testing.T) {
	root := t.TempDir()
	ignored := filepath.Join(root, ".git")
	if err := os.Mkdir(ignored, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ignored, ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config")
	var content strings.Builder
	for _, v := range required {
		content.WriteString("--iglob=!" + v + "\n")
	}
	if err := os.WriteFile(config, []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}
	if reason := Scope([]string{"rg", "TOKEN", ".git"}, root, root, config, false); reason == "" {
		t.Fatal("explicit ignored root bypassed scan")
	}
	if reason := Scope([]string{"rg", "TOKEN", "."}, root, root, config, true); reason == "" {
		t.Fatal("inline config change allowed")
	}
}

func TestToolSelectors(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		selector  string
		protected bool
	}{
		{"**/.config/gh/*.yml", true}, {"**/.env*", true}, {"src/.env*", true}, {".ENV*", true}, {"proc/$PPID/environ", true},
		{"**/environment*.ts", false}, {"~/.ssh/id_ed25519.pub", false},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			if got := Selector(tc.selector); got != tc.protected {
				t.Fatalf("selector protected=%t, want %t", got, tc.protected)
			}
		})
	}
	if ToolGlob(".env", root, root) == "" {
		t.Fatal("explicit protected Glob root allowed")
	}
	if ToolGlob("src", root, root) != "" {
		t.Fatal("unrelated Glob root denied")
	}
}

func TestToolGrepAlias(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, ".env")
	if err := os.WriteFile(protected, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias.txt")
	if err := os.Symlink(protected, alias); err != nil {
		t.Fatal(err)
	}
	if reason := ToolGrep(alias, "", "", "files_with_matches", root, root); reason != "" {
		t.Fatal(reason)
	}
	if reason := ToolGrep(alias, "", "", "count", root, root); reason == "" {
		t.Fatal("count allowed")
	}
}
