package backend

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/store"
)

const testAccount = "0123456789abcdef0123456789abcdef"

// TestLibsecretCommands checks exact attributes, stdin transport and value-free errors.
func TestLibsecretCommands(t *testing.T) {
	var calls []string
	p := libsecret{run: func(name string, args []string, input []byte) ([]byte, []byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch args[0] {
		case "lookup":
			return []byte("synthetic"), nil, nil
		case "store":
			if !bytes.Equal(input, []byte("synthetic")) {
				t.Error("store stdin mismatch")
			}
		}
		return nil, nil, nil
	}}
	if err := p.Put("secret/demo", testAccount, "secret demo TOKEN [env=dev]", []byte("synthetic\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := p.Get("secret/demo", testAccount); err != nil || !bytes.Equal(got, []byte("synthetic")) {
		t.Fatal("lookup mismatch", err)
	}
	if err := p.Delete("secret/demo", testAccount); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"secret-tool store --label=secret demo TOKEN [env=dev] service secret/demo account " + testAccount,
		"secret-tool lookup service secret/demo account " + testAccount,
		"secret-tool clear service secret/demo account " + testAccount,
	}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	failure := libsecret{run: func(string, []string, []byte) ([]byte, []byte, error) {
		return nil, []byte("synthetic-secret"), errors.New("synthetic-secret")
	}}
	if _, err := failure.Get("secret/demo", testAccount); err == nil || bytes.Contains([]byte(err.Error()), []byte("synthetic")) {
		t.Error("lookup exposed provider error")
	}
	if err := failure.Put("secret/demo", testAccount, "secret demo TOKEN", []byte("synthetic")); err == nil || bytes.Contains([]byte(err.Error()), []byte("synthetic")) {
		t.Error("put exposed provider error")
	}
	if err := failure.Delete("secret/demo", testAccount); err == nil || bytes.Contains([]byte(err.Error()), []byte("synthetic")) {
		t.Error("delete exposed provider error")
	}
	if _, err := p.Get("secret/demo", "-bad"); err == nil {
		t.Error("invalid account accepted")
	}
}

// TestLibsecretIntegration runs only with an isolated disposable D-Bus/keyring.
func TestLibsecretIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_LIBSECRET") != "1" {
		t.Skip("isolated libsecret CI only")
	}
	root := os.Getenv("SECRET_TEST_ROOT")
	if os.Getenv("SECRET_TEST_CHILD") != "1" {
		for _, name := range []string{"dbus-run-session", "gnome-keyring-daemon", "secret-tool"} {
			if _, err := exec.LookPath(name); err != nil {
				t.Fatalf("missing %s: %v", name, err)
			}
		}
		root = t.TempDir()
		for _, path := range []string{"home", "data", "run", "config"} {
			if err := os.Mkdir(filepath.Join(root, path), 0700); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "dbus-run-session", "--", os.Args[0], "-test.run=^TestLibsecretIntegration$")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + filepath.Join(root, "home"), "XDG_DATA_HOME=" + filepath.Join(root, "data"), "XDG_RUNTIME_DIR=" + filepath.Join(root, "run"), "XDG_CONFIG_HOME=" + filepath.Join(root, "config"), "SECRET_TEST_ROOT=" + root, "SECRET_TEST_CHILD=1", "SECRET_REQUIRE_LIBSECRET=1"}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated session failed: %v: %s", err, out)
		}
		return
	}
	if root == "" || os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" || os.Getenv("HOME") != filepath.Join(root, "home") || os.Getenv("XDG_DATA_HOME") != filepath.Join(root, "data") || os.Getenv("XDG_RUNTIME_DIR") != filepath.Join(root, "run") || os.Getenv("XDG_CONFIG_HOME") != filepath.Join(root, "config") {
		t.Fatal("private bus and temporary HOME required")
	}
	for _, path := range []string{"home", "data", "run", "config"} {
		info, err := os.Lstat(filepath.Join(root, path))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("temporary provider directory required")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gnome-keyring-daemon", "--unlock", "--components=secrets")
	cmd.Stdin = bytes.NewReader([]byte{'\n'})
	if err := cmd.Run(); err != nil {
		t.Fatalf("temporary keyring failed: %v", err)
	}
	p, _, _, err := Dispatch("libsecret:demo")
	if err != nil {
		t.Fatal(err)
	}
	const value = "synthetic-é-$TOKEN"
	dir := filepath.Join(root, "home", ".secrets")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Stash(dir, "libsecret:demo", "TOKEN", map[string]string{"env": "dev"}, []byte(value), nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.ReadManifest(filepath.Join(dir, "demo.keys"), "libsecret")
	if err != nil || len(records) != 1 {
		t.Fatalf("manifest: %v", err)
	}
	got, err := p.Get("secret/demo", records[0].Account)
	if err != nil || !bytes.Equal(got, []byte(value)) {
		t.Fatal("roundtrip failed", err)
	}
	if _, err := p.Get("secret/other", records[0].Account); err == nil {
		t.Error("wrong service resolved")
	}
	if err := p.Delete("secret/demo", records[0].Account); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get("secret/demo", records[0].Account); err == nil {
		t.Error("deleted item resolved")
	}
}
