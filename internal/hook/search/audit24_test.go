package search

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit24CertifiedExplicitAWSRoot(t *testing.T) {
	home := t.TempDir()
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	config := filepath.Join(home, "synthetic-rg-config")
	text := "--hidden\n"
	for _, pattern := range required {
		text += "--iglob=!" + pattern + "\n"
	}
	if err := os.WriteFile(config, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{".aws", ".ssh", ".kube", "public"} {
		root := filepath.Join(home, directory)
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal(err)
		}
		for _, words := range [][]string{{"rg", "KEY", root}, {"rg", "-n", "aws_secret", root}, {"rg", "-l", "KEY", root}, {"rg", "--files", root}} {
			wantDeny := directory == ".aws" && words[1] != "-l" && words[1] != "--files"
			if reason := Scope(words, home, home, config, false); (reason != "") != wantDeny {
				t.Errorf("%v: reason=%q want deny=%v", words, reason, wantDeny)
			}
		}
	}
	aws := filepath.Join(home, ".aws")
	if reason := Scope([]string{"rg", "KEY"}, aws, home, config, false); reason == "" {
		t.Error("implicit cwd inside protected AWS root allowed")
	}
}
