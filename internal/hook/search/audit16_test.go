package search

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit16MixedGlobConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env.ts"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	var config strings.Builder
	config.WriteString("--hidden\n")
	for _, glob := range required {
		config.WriteString("--iglob=!" + glob + "\n")
	}
	file := filepath.Join(root, "rg-options")
	if err := os.WriteFile(file, []byte(config.String()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		glob string
		deny bool
	}{{"!*.md", false}, {"!.env", false}, {"{*.ts,!*.md}", true}, {"{!*.md,*.ts}", true}} {
		if got := Scope([]string{"rg", "-g", tc.glob, "KEY"}, root, root, file, false); (got != "") != tc.deny {
			t.Errorf("glob=%q denial=%q want deny=%v", tc.glob, got, tc.deny)
		}
	}
}

func TestAudit16FilteredScopes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", ".env.ts", "src/a.ts", "src/README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, glob, typ string
		deny            bool
	}{
		{"A1 negative", "!*.md", "", true},
		{"A1 negative braces", "!*.{md,txt}", "", true},
		{"A1 brace alternative", "{src/**,!*.md}", "", true},
		{"A1 public", "src/*.ts", "", false},
		{"A2 negated class", "[!_]*.ts", "", true},
		{"A2 public class", "src/[!_]*.ts", "", false},
		{"B4 markdown type", "", "md", false},
		{"B4 protected type", "", "env", true},
		{"B6 subtree", "src/**", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ToolGrep(".", tc.glob, tc.typ, "content", root, root); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
	if err := os.WriteFile(filepath.Join(root, "src", ".env"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ToolGrep(".", "src/**", "", "content", root, root); got == "" {
		t.Fatal("subtree glob allowed a protected file within the subtree")
	}
}
