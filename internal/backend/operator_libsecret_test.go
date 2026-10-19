//go:build linux

package backend_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorLibsecretIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_LIBSECRET") != "1" {
		t.Skip("isolated libsecret CI only")
	}
	if os.Getenv("SECRET_OPERATOR_CHILD") != "1" {
		for _, name := range []string{"dbus-run-session", "gnome-keyring-daemon", "secret-tool"} {
			if _, err := exec.LookPath(name); err != nil {
				t.Fatal("required isolated-provider dependency missing")
			}
		}
		root := t.TempDir()
		for _, name := range []string{"home", "data", "run", "config"} {
			if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "dbus-run-session", "--", os.Args[0], "-test.v", "-test.run=^TestOperatorLibsecretIntegration$")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "XDG_DATA_HOME=" + filepath.Join(root, "data"), "XDG_RUNTIME_DIR=" + filepath.Join(root, "run"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "SECRET_OPERATOR_ROOT=" + root, "SECRET_OPERATOR_CHILD=1", "SECRET_REQUIRE_LIBSECRET=1"}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated operator session failed: %v: %s", err, output)
		}
		return
	}
	root := os.Getenv("SECRET_OPERATOR_ROOT")
	if root == "" || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatal("private bus and temporary HOME required")
	}
	for variable, name := range map[string]string{"HOME": "home", "XDG_DATA_HOME": "data", "XDG_RUNTIME_DIR": "run", "XDG_CONFIG_HOME": "config"} {
		path := filepath.Join(root, name)
		info, err := os.Lstat(path)
		if os.Getenv(variable) != path || err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			t.Fatal("private temporary provider directories required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gnome-keyring-daemon", "--unlock", "--components=secrets")
	cmd.Stdin = bytes.NewReader([]byte{'\n'})
	if err := cmd.Run(); err != nil {
		t.Fatal("temporary keyring unlock failed")
	}
	runProviderOperators(t, root, "libsecret")
}
