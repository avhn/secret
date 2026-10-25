package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
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
	dir := testutil.TempDir(t)
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
	if err := testutil.WriteFile(path, content[:len(content)-1], 0600); err != nil {
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
		assertPrivateFixture(t, path)
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
		t.Fatal("required Windows symlink fixture unavailable")
	}
	notFile := filepath.Join(dir, "directory.keys")
	if err := testutil.Mkdir(notFile, 0700); err != nil {
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

func TestWholeManifestPublication(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.keys")
	prior := []ManifestRecord{{Key: "KEY", Account: "11111111111111111111111111111111"}}
	if err := WithWriteLock(dir, func() error { return PublishManifestLocked(path, "libsecret", prior) }); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, records := range [][]ManifestRecord{
		{{Key: "BAD-KEY", Account: prior[0].Account}},
		{{Key: "KEY", Account: "not-an-account"}},
		{prior[0], prior[0]},
		{prior[0], {Key: "OTHER", Account: prior[0].Account}},
		{prior[0], {Key: "KEY", Account: "22222222222222222222222222222222"}},
	} {
		if err := WithWriteLock(dir, func() error { return PublishManifestLocked(path, "libsecret", records) }); err == nil {
			t.Error("invalid whole inventory accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("failed batch changed the previous manifest")
		}
	}
	if err := WithWriteLock(dir, func() error { return PublishManifestLocked(path, "libsecret", nil) }); err != nil {
		t.Fatal(err)
	}
	records, err := ReadManifest(path, "libsecret")
	if err != nil || len(records) != 0 {
		t.Fatal("empty whole inventory was not published")
	}
}

func TestManifestEditorRecoveryProtocol(t *testing.T) {
	path := filepath.Join(testutil.TempDir(t), "synthetic.keys")
	prepared := ManifestRecord{Key: "NEW", Labels: map[string]string{"env": "dev"}, Account: "22222222222222222222222222222222"}
	intent := RecoveryIntent{Version: MetadataVersion, Backend: "keychain", Prepared: []ManifestRecord{prepared}}
	var expired *ManifestEditor
	if err := WithManifestLock(path, "keychain", func(editor *ManifestEditor) error {
		expired = editor
		if err := editor.Publish([]ManifestRecord{prepared}); err != secure.ErrRecovery {
			t.Fatal("publish before recovery was accepted")
		}
		if err := editor.PersistRecovery(intent); err != nil {
			return err
		}
		if err := editor.ClearRecovery(); err != secure.ErrRecovery {
			t.Fatal("cleared recovery before publication")
		}
		got, err := ReadRecovery(path, "keychain")
		if err != nil || len(got.Prepared) != 1 || got.Prepared[0].Account != prepared.Account {
			t.Fatal("persisted recovery intent differs")
		}
		assertPrivateFixture(t, path+".recovery")
		if err := editor.PersistRecovery(intent); err != secure.ErrRecovery {
			t.Fatal("overwrote existing recovery")
		}
		if err := editor.Publish([]ManifestRecord{prepared}); err != nil {
			return err
		}
		return editor.ClearRecovery()
	}); err != nil {
		t.Fatal(err)
	}
	if expired.Publish(nil) != secure.ErrRecovery || expired.PersistRecovery(intent) != secure.ErrRecovery || expired.ClearRecovery() != secure.ErrRecovery {
		t.Fatal("expired editor accepted mutation")
	}
	if _, err := ReadRecovery(path, "keychain"); !os.IsNotExist(err) {
		t.Fatal("completed transaction left recovery intent")
	}
	// Retaining incomplete intent can never report a successful transaction.
	if err := WithManifestLock(path, "keychain", func(editor *ManifestEditor) error {
		return editor.PersistRecovery(intent)
	}); err != secure.ErrRecovery {
		t.Fatalf("incomplete transaction result: %v", err)
	}
	called := false
	if err := WithManifestLock(path, "keychain", func(*ManifestEditor) error { called = true; return nil }); err != secure.ErrRecovery || called {
		t.Fatal("pending recovery did not block callback")
	}
}

func TestRecoveryValidationAndAliases(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		mode       os.FileMode
	}{
		{"invalid version", `{"version":2,"backend":"keychain","prepared":[],"obsolete":[]}`, 0600},
		{"backend mismatch", `{"version":1,"backend":"libsecret","prepared":[],"obsolete":[]}`, 0600},
		{"unexpected field", `{"version":1,"backend":"keychain","value":"synthetic-sentinel"}`, 0600},
		{"trailing document", `{"version":1,"backend":"keychain"} {}`, 0600},
		{"unprotected", `{"version":1,"backend":"keychain"}`, 0644},
		{"oversize", strings.Repeat(" ", recoveryLimit+1), 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(testutil.TempDir(t), "synthetic.keys")
			if err := testutil.WriteFile(path+".recovery", []byte(tc.body), tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadRecovery(path, "keychain"); err != secure.ErrRecovery {
				t.Fatalf("invalid recovery result: %v", err)
			}
		})
	}
	path := filepath.Join(testutil.TempDir(t), "synthetic.keys")
	if err := os.Symlink("missing", path+".recovery"); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRecovery(path, "keychain"); err != secure.ErrRecovery {
		t.Fatal("followed aliased recovery")
	}
	if err := WithManifestLock(path, "keychain", func(*ManifestEditor) error { t.Fatal("aliased recovery allowed mutation"); return nil }); err != secure.ErrRecovery {
		t.Fatal("aliased recovery did not block transaction")
	}
	// Recovery validates exact names and cross-phase account uniqueness.
	record := ManifestRecord{Key: "KEY", Account: "11111111111111111111111111111111"}
	if validateRecovery(RecoveryIntent{Version: MetadataVersion, Backend: "keychain", Prepared: []ManifestRecord{record}, Obsolete: []ManifestRecord{record}}, "keychain") != secure.ErrRecovery {
		t.Fatal("recovery account collision accepted")
	}
	data, err := json.Marshal(RecoveryIntent{Version: MetadataVersion, Backend: "keychain", Prepared: []ManifestRecord{record}})
	if err != nil || bytes.Contains(data, []byte("synthetic-sentinel")) || bytes.Contains(data, []byte("value")) || bytes.Contains(data, []byte("length")) || bytes.Contains(data, []byte("digest")) {
		t.Fatal("recovery contains value-bearing metadata")
	}
}
