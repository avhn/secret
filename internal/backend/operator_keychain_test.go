//go:build darwin

package backend_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestOperatorKeychainIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_KEYCHAIN") != "1" {
		t.Skip("isolated macOS Keychain CI only")
	}
	tool, err := exec.LookPath("security")
	if err != nil {
		t.Fatal("required Keychain executable missing")
	}
	root := t.TempDir()
	path := filepath.Join(root, "operator.keychain-db")
	if !regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`).MatchString(path) {
		t.Fatal("unsafe disposable keychain path")
	}
	security := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, tool, args...).Run() != nil {
			t.Fatal("temporary keychain operation failed")
		}
	}
	security("create-keychain", "-p", "synthetic-test-pass", path)
	t.Cleanup(func() { security("delete-keychain", path) })
	security("unlock-keychain", "-p", "synthetic-test-pass", path)
	security("set-keychain-settings", path)
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRET_KEYCHAIN", path)
	// Never set the user's default keychain or alter the search list.
	runProviderOperators(t, root, "keychain")
}
