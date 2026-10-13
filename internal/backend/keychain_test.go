package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/store"
)

// TestKeychainCommands checks -g decoding, -i transport, validation and errors on every OS.
func TestKeychainCommands(t *testing.T) {
	const value = "synthetic-é-$TOKEN"
	var calls []string
	var supplied []byte
	p := keychain{path: "/tmp/disposable.keychain-db", valid: true}
	p.run = func(name string, args []string, input []byte) ([]byte, []byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "security" {
			t.Error("wrong executable")
		}
		switch args[0] {
		case "-i":
			supplied = bytes.Clone(input)
			return nil, nil, nil
		case "find-generic-password":
			return nil, []byte("keychain: synthetic\npassword: 0x" + hex.EncodeToString([]byte(value)) + "\n"), nil
		}
		return nil, nil, nil
	}
	if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN/env=dev", []byte(value)); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(supplied, []byte("add-generic-password -U -s secret/demo -a "+testAccount+" -l secret/demo/TOKEN/env=dev -X ")) || !bytes.HasSuffix(supplied, []byte(" /tmp/disposable.keychain-db\n")) || bytes.Contains(supplied, []byte(value)) {
		t.Error("unsafe -i input")
	}
	if len(supplied) > 4000 {
		t.Error("long security command")
	}
	if err := p.Delete("secret/demo", testAccount); err != nil {
		t.Fatal(err)
	}
	want := []string{"security -i", "security find-generic-password -s secret/demo -a " + testAccount + " -g /tmp/disposable.keychain-db", "security delete-generic-password -s secret/demo -a " + testAccount + " /tmp/disposable.keychain-db"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
	for _, tc := range []struct{ raw, want string }{
		{"password: \"synthetic\"\n", "synthetic"},
		{"password: \"0x6162\"\n", "0x6162"},
		{"password: 0x6162\n", "ab"},
		{"password: 0xC3A9 other text\n", "é"},
	} {
		got, err := parseKeychainPassword([]byte(tc.raw))
		if err != nil || string(got) != tc.want {
			t.Errorf("parse format failed: %v", err)
		}
	}
	for _, raw := range []string{"password: garbage", "password: 0xzz", "password: 0xabc", "no password here"} {
		if _, err := parseKeychainPassword([]byte(raw)); err == nil {
			t.Error("malformed -g response accepted")
		}
	}
	failure := keychain{path: p.path, valid: true, run: func(string, []string, []byte) ([]byte, []byte, error) { return nil, []byte(value), errors.New(value) }}
	if _, err := failure.Get("secret/demo", testAccount); err == nil || strings.Contains(err.Error(), value) {
		t.Error("lookup leaked value")
	}
	if err := failure.Put("secret/demo", testAccount, "secret/demo/TOKEN", []byte(value)); err == nil || strings.Contains(err.Error(), value) {
		t.Error("put leaked value")
	}
	if err := failure.Delete("secret/demo", testAccount); err == nil || strings.Contains(err.Error(), value) {
		t.Error("delete leaked value")
	}
	for _, bad := range []string{"synthetic\tcontrol", "\xffsynthetic", "synthetic\u0085control", strings.Repeat("q", 1801)} {
		if err := p.Put("secret/demo", testAccount, "secret/demo/TOKEN", []byte(bad)); err == nil {
			t.Error("invalid keychain value accepted")
		}
	}
	if _, err := (keychain{run: p.run, valid: false}).Get("secret/demo", testAccount); err == nil {
		t.Error("invalid path accepted")
	}
}

// TestKeychainIntegration uses a temporary explicit keychain without changing the search list.
func TestKeychainIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_KEYCHAIN") != "1" {
		t.Skip("isolated macOS Keychain CI only")
	}
	if runtime.GOOS != "darwin" {
		t.Fatal("macOS is required")
	}
	if _, err := exec.LookPath("security"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "disposable.keychain-db")
	if !keychainPath.MatchString(path) {
		t.Fatal("unsafe temporary keychain path")
	}
	security := func(args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "security", args...)
		if err := cmd.Run(); err != nil {
			return errors.New("temporary keychain operation failed")
		}
		return nil
	}
	if err := security("create-keychain", "-p", "synthetic-test-pass", path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := security("delete-keychain", path); err != nil {
			t.Error(err)
		}
	})
	if err := security("unlock-keychain", "-p", "synthetic-test-pass", path); err != nil {
		t.Fatal(err)
	}
	if err := security("set-keychain-settings", path); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_KEYCHAIN", path)
	t.Setenv("HOME", filepath.Join(root, "home"))
	dir := filepath.Join(root, "home", ".secrets")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	const value = "synthetic-é-$TOKEN"
	if err := Stash(dir, "keychain:demo", "TOKEN", map[string]string{"env": "dev"}, []byte(value), nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.ReadManifest(filepath.Join(dir, "demo.keys"), "keychain")
	if err != nil || len(records) != 1 {
		t.Fatalf("manifest: %v", err)
	}
	p, _, _, err := Dispatch("keychain:demo")
	if err != nil {
		t.Fatal(err)
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
