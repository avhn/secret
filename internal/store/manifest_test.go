package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManifestValidation(t *testing.T) {
	const header = "secret-manifest-v1\nbackend=keychain\n"
	const id = "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, body, backend string
		valid               bool
	}{
		{"empty", header, "keychain", true},
		{"record", header + "KEY\tenv=prod,zone=west\t" + id + "\n", "keychain", true},
		{"wrong header", "secret-manifest-v2\nbackend=keychain\n", "keychain", false},
		{"backend mismatch", header, "libsecret", false},
		{"missing header", "", "keychain", false},
		{"last record without newline", header + "KEY\t\t" + id, "keychain", true},
		{"extra field", header + "KEY\t\t" + id + "\textra\n", "keychain", false},
		{"bad key", header + "BAD-NAME\t\t" + id + "\n", "keychain", false},
		{"noncanonical labels", header + "KEY\tzone=west,env=prod\t" + id + "\n", "keychain", false},
		{"duplicate label", header + "KEY\tenv=prod,env=qa\t" + id + "\n", "keychain", false},
		{"bad account", header + "KEY\t\t" + strings.ToUpper(id) + "\n", "keychain", false},
		{"duplicate identity", header + "KEY\t\t" + id + "\nKEY\t\t" + "11111111111111111111111111111111" + "\n", "keychain", false},
		{"duplicate account", header + "KEY\t\t" + id + "\nOTHER\t\t" + id + "\n", "keychain", false},
		{"blank row", header + "\n", "keychain", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tc.body), tc.backend)
			if (err == nil) != tc.valid {
				t.Errorf("valid = %v", err == nil)
			}
		})
	}
}
func TestManifestPublish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.keys")
	a, err := NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err = UpdateManifest(path, "libsecret", "KEY", map[string]string{"env": "dev"}, a); err != nil {
		t.Fatal(err)
	}
	b, err := NewAccount()
	if err != nil || a == b {
		t.Fatal("random account collision or failure")
	}
	if err = UpdateManifest(path, "libsecret", "NEXT", nil, b); err != nil {
		t.Fatal(err)
	}
	// The Bash reader accepts a final TSV row without LF; publishing normalizes it.
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content[:len(content)-1], 0600); err != nil {
		t.Fatal(err)
	}
	c, err := NewAccount()
	if err != nil {
		t.Fatal(err)
	}
	if err := UpdateManifest(path, "libsecret", "THIRD", nil, c); err != nil {
		t.Fatal(err)
	}
	records, err := ReadManifest(path, "libsecret")
	if err != nil || len(records) != 3 {
		t.Fatalf("manifest read = %d, %v", len(records), err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0600 {
			t.Error("manifest mode must be 0600")
		}
	} else {
		t.Log("Windows file ACLs do not expose Unix permission bits")
	}
	if err = UpdateManifest(path, "keychain", "OTHER", nil, b); err == nil {
		t.Error("backend mismatch accepted")
	}
	if err = UpdateManifest(path, "libsecret", "OTHER", nil, b); err == nil {
		t.Error("duplicate account accepted")
	}
	if err = UpdateManifest(path, "libsecret", "KEY", map[string]string{"env": "dev"}, b); err == nil {
		t.Error("existing identity account replaced")
	}
	linked := filepath.Join(dir, "linked.keys")
	if err := os.Symlink(path, linked); err == nil {
		if _, err := ReadManifest(linked, "libsecret"); err == nil {
			t.Error("symlink manifest accepted")
		}
	} else if runtime.GOOS == "windows" {
		t.Log("symlink creation unavailable without Windows developer privileges")
	}
	notFile := filepath.Join(dir, "directory.keys")
	if err := os.Mkdir(notFile, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(notFile, "libsecret"); err == nil {
		t.Error("nonregular manifest accepted")
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadManifest(path, "libsecret"); err == nil {
			t.Error("permissive mode accepted")
		}
	} else {
		t.Log("Windows file ACLs do not expose Unix permission bits")
	}
}
