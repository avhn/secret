package search

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit20AWSConfigSearch(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".aws/config", "custom.ini", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "custom.ini")
			for _, tc := range []struct {
				glob string
				deny bool
			}{{"*.ini", true}, {"**/config", true}, {"*.md", false}} {
				if reason := ToolGrep(root, tc.glob, "", "content", root, root); (reason != "") != tc.deny {
					t.Errorf("glob=%q reason=%q, deny=%v", tc.glob, reason, tc.deny)
				}
			}
			if reason := ToolGrep(root, "", "", "content", root, root); reason == "" {
				t.Error("unfiltered credential scope allowed")
			}
		})
	}
	if !Selector("**/.aws/config") {
		t.Error("AWS config selector lost its protected witness")
	}
}
