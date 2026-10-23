package search

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit28GHConfigCertification(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "XDG_CONFIG_HOME", "GH_CONFIG_DIR"} {
		t.Setenv(key, "")
	}
	config := filepath.Join(root, "rg-config")
	var content strings.Builder
	for _, glob := range required {
		content.WriteString("--iglob=!" + glob + "\n")
	}
	if err := os.WriteFile(config, []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		directory string
		status    int
	}{
		{"", 0}, {filepath.Join(root, "custom"), 1},
	} {
		t.Setenv("GH_CONFIG_DIR", tc.directory)
		if status, _ := Config(config, root, root); status != tc.status {
			t.Errorf("status=%d, want %d", status, tc.status)
		}
	}
}
