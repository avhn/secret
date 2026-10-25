package store

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
)

func TestManifestPaths(t *testing.T) {
	for _, tc := range []struct{ ref, file string }{
		{"keychain:demo", "demo.keys"}, {"libsecret:demo", "demo.keys"},
		{"pass:demo", "demo.pass-keys"}, {"age:demo", ""}, {"onepassword:demo", ""},
		{"wincred:demo", "demo.wincred-keys"}, {"wincred:_demo-1.2", "_demo-1.2.wincred-keys"},
		{"wincred:", ""}, {"wincred:../demo", ""}, {"wincred:demo:other", ""},
		{"wincred:demo\\other", ""}, {"file:demo", ""}, {"unknown:demo", ""},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			path, err := ManifestPath("inventories", tc.ref)
			if tc.file == "" {
				if err == nil {
					t.Fatal("invalid reference accepted")
				}
			} else if err != nil || path != filepath.Join("inventories", tc.file) {
				t.Fatal("incorrect manifest mapping")
			}
		})
	}
}

func TestReservedWincredNeverBecomesFile(t *testing.T) {
	locator := Locator{IsFile: func(string) bool { t.Fatal("provider reference probed a plaintext file"); return false }}
	for _, ref := range []string{"wincred:synthetic", "wincred:", "wincred:../synthetic", "wincred:synthetic:other"} {
		resolved, err := locator.Resolve(ref)
		// The inactive manifest step may reject a reserved reference. Once
		// transport dispatch is wired it must preserve it, never return a path.
		if err != nil && !errors.Is(err, ErrInvalidKeystoreName) {
			t.Fatal("unexpected reserved-reference error")
		}
		if err == nil && resolved != ref {
			t.Fatal("reserved provider reference became a plaintext path")
		}
	}
}

func TestWincredManifestRecovery(t *testing.T) {
	dir := testutil.TempDir(t)
	path, err := ManifestPath(dir, "wincred:synthetic")
	if err != nil {
		t.Fatal(err)
	}
	records := []ManifestRecord{{Key: "TOKEN", Labels: map[string]string{"env": "test"}, Account: "0123456789abcdef0123456789abcdef"}}
	data, err := EncodeManifest(records, "wincred")
	if err != nil || !bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=wincred\n")) {
		t.Fatal("invalid wincred v1 encoding")
	}
	for _, kind := range []string{"keychain", "libsecret", "pass", "age", "unknown"} {
		if _, err := ParseManifest(data, kind); err == nil {
			t.Fatal("backend mismatch accepted")
		}
	}
	intent := RecoveryIntent{Version: MetadataVersion, Backend: "wincred", Prepared: records}
	err = WithManifestLock(path, "wincred", func(editor *ManifestEditor) error { return editor.PersistRecovery(intent) })
	if !errors.Is(err, secure.ErrRecovery) {
		t.Fatal("pending recovery not reported")
	}
	got, err := ReadRecovery(path, "wincred")
	if err != nil || !reflect.DeepEqual(got, intent) {
		t.Fatal("names-only recovery mismatch")
	}
	called := false
	err = WithManifestLock(path, "wincred", func(*ManifestEditor) error { called = true; return nil })
	if !errors.Is(err, secure.ErrRecovery) || called {
		t.Fatal("pending recovery did not block mutation")
	}
	if err := os.Remove(path + ".recovery"); err != nil {
		t.Fatal(err)
	}
	if err := WithManifestLock(path, "wincred", func(editor *ManifestEditor) error {
		if err := editor.PersistRecovery(intent); err != nil {
			return err
		}
		if err := editor.Publish(records); err != nil {
			return err
		}
		return editor.ClearRecovery()
	}); err != nil {
		t.Fatal(err)
	}
	read, err := ReadManifest(path, "wincred")
	if err != nil || !reflect.DeepEqual(read, records) {
		t.Fatal("manifest round trip failed")
	}
	if _, err := ReadRecovery(path, "wincred"); !os.IsNotExist(err) {
		t.Fatal("completed recovery retained")
	}
	if matches, err := filepath.Glob(filepath.Join(dir, "*.keys")); err != nil || len(matches) != 0 {
		t.Fatal("wincred entered Bash discovery")
	}
}

func TestWincredOutsideBashDiscovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unchanged Bash compatibility is a Unix lane")
	}
	dir := testutil.TempDir(t)
	id := "0123456789abcdef0123456789abcdef"
	for _, kind := range []string{"keychain", "libsecret", "wincred"} {
		path, err := ManifestPath(dir, kind+":synthetic-"+kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := UpdateManifest(path, kind, "TOKEN", nil, id); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "synthetic.secret")
	if err := testutil.WriteFile(file, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join("..", "..", "bin", "secret"), "list")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "SECRETS_DIR=" + dir, "SECRETS_ENV=" + filepath.Join(dir, "missing.env")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("unchanged Bash discovery failed")
	}
	for _, want := range []string{"keychain:synthetic-keychain", "libsecret:synthetic-libsecret", file} {
		if !strings.Contains(string(out), want) {
			t.Fatal("existing Bash store disappeared")
		}
	}
	if bytes.Contains(out, []byte("wincred")) {
		t.Fatal("Bash discovered wincred inventory")
	}
}

func TestReservedBackendNeverProbesPlaintext(t *testing.T) {
	locator := Locator{IsFile: func(string) bool { t.Fatal("reserved reference probed plaintext"); return false }}
	for _, kind := range []string{"pass", "age", "wincred", "onepassword"} {
		for _, name := range []string{"synthetic", "", "../synthetic", "synthetic:other"} {
			ref := kind + ":" + name
			resolved, err := locator.Resolve(ref)
			if err == nil && resolved != ref {
				t.Fatalf("reserved %s reference became a file", kind)
			}
			if name != "synthetic" && err == nil {
				t.Fatalf("invalid %s reference accepted", kind)
			}
		}
	}
}

func TestProviderManifestClassification(t *testing.T) {
	for _, kind := range []string{"keychain", "libsecret", "pass", "wincred"} {
		if !manifestBackend(kind) || !providerManifestBackend(kind) || !ProviderReference(kind+":synthetic") {
			t.Fatalf("standalone provider %s was not classified", kind)
		}
	}
	if !manifestBackend("age") || providerManifestBackend("age") || ProviderReference("age:synthetic") {
		t.Fatal("age grammar and storage path classifications were conflated")
	}
	if manifestBackend("onepassword") || providerManifestBackend("onepassword") || ProviderReference("onepassword:synthetic") {
		t.Fatal("v2 provider entered the v1 mapping")
	}
}
