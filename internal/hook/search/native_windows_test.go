//go:build windows

package search

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsFileSearchIdentityMode(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	configured := filepath.Join(root, "custom.cfg")
	for _, name := range []string{configured, filepath.Join(root, "README.md")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(configured, filepath.Join(root, "public.ts")); err != nil {
		t.Fatalf("required identity alias: %v", err)
	}
	t.Setenv("KUBECONFIG", configured)
	if reason := FilteredScope(root, "*.ts", "", root, root); reason != "" {
		t.Fatalf("Bash search gained native file identity: %s", reason)
	}
	for _, tc := range []struct {
		glob, mode string
		deny       bool
	}{
		{"*.ts", "content", true},
		{"*.ts", "count", true},
		{"*.ts", "files_with_matches", false},
		{"*.md", "content", false},
	} {
		t.Run(tc.glob+"/"+tc.mode, func(t *testing.T) {
			if reason := ToolGrep(root, tc.glob, "", tc.mode, root, root); (reason != "") != tc.deny {
				t.Errorf("native search reason=%q want deny=%v", reason, tc.deny)
			}
		})
	}
	for _, tc := range []struct {
		name string
		deny bool
	}{
		{"public.ts", true},
		{"README.md", false},
	} {
		if reason := ToolGlob(tc.name, root, root); (reason != "") != tc.deny {
			t.Errorf("native Glob %s: reason=%q want deny=%v", tc.name, reason, tc.deny)
		}
	}
}
