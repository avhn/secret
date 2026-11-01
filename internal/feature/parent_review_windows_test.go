//go:build windows

package feature

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsTrustedParentDoctorAndRejection(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.secret")
	if err := testutil.WriteFile(path, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := doctorPrivateStatus(dir); got != "private" {
		t.Fatalf("private directory status: %s", got)
	}
	testutil.TrustStoreParent(t, dir, true)
	var checks []DoctorCheck
	doctorPath(dir, func(kind, target, status, detail string) {
		checks = append(checks, DoctorCheck{kind, target, status, detail})
	})
	encoded, err := json.Marshal(checks)
	if err != nil || !bytes.Contains(encoded, []byte(`"status":"trusted_parent"`)) {
		t.Fatal("doctor JSON did not classify trusted parent")
	}
	if got := doctorPrivateStatus(path); got != "private" {
		t.Fatalf("store file status: %s", got)
	}
	if _, err := readOperatorFile(path, false); err != nil {
		t.Fatal(err)
	}
	testutil.AddStoreParentUsersRead(t, dir)
	if got := doctorPrivateStatus(dir); got != "insecure" {
		t.Fatalf("outsider directory status: %s", got)
	}
	if _, err := store.ReadFile(path); err == nil {
		t.Fatal("store read accepted Users read ACE")
	}
	if err := store.StashWithSecretsDir(dir, path, "TOKEN", nil, []byte("must-not-publish")); err == nil {
		t.Fatal("stash accepted Users read ACE")
	}
	if _, err := readOperatorFile(path, false); err == nil {
		t.Fatal("operator read accepted Users read ACE")
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, []byte("TOKEN=synthetic\n")) {
		t.Fatal("rejected operation changed fixture")
	}
}

func TestWindowsDoctorArtifactPublicParent(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic-launcher.exe")
	content := []byte("synthetic-public-artifact")
	if err := testutil.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	testutil.TrustStoreParent(t, dir, false)
	testutil.AddStoreParentUsersRead(t, dir)
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)
	digest := sha256.Sum256(content)
	matched := false
	doctorArtifact(DoctorArtifact{Kind: "go_launcher", Path: path, ExpectedSHA256: hex.EncodeToString(digest[:])}, DoctorOptions{Home: filepath.Dir(dir), Cwd: dir}, func(kind, target, status, detail string) {
		if kind == "checksum" {
			if status != "matched" {
				t.Fatalf("public artifact checksum: %s", status)
			}
			matched = true
		}
	})
	if !matched {
		t.Fatal("artifact checksum not inspected")
	}
	alias := filepath.Join(filepath.Dir(dir), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	root, err := openDoctorArtifactParent(filepath.Join(alias, filepath.Base(path)))
	if err != nil {
		t.Fatal("doctor artifact parent lost resolved-alias semantics")
	}
	root.Close()
	if root, err := openOperatorParent(path); err == nil {
		root.Close()
		t.Fatal("store policy accepted public artifact parent")
	}
}

func TestWindowsOperatorVolumeRootPolicy(t *testing.T) {
	for _, path := range []string{`C:\`, `\\synthetic\share\`} {
		t.Run(path, func(t *testing.T) {
			dir := testutil.TempDir(t)
			testutil.TrustStoreParent(t, dir, false)
			calls := 0
			opener := func(name string) (*os.Root, error) {
				calls++
				if name != path {
					t.Fatalf("unexpected root %q", name)
				}
				return os.OpenRoot(dir)
			}
			root, err := openOperatorDirectoryWithRoot(path, opener)
			if err != nil {
				t.Fatal(err)
			}
			root.Close()
			testutil.AddStoreParentUsersRead(t, dir)
			if root, err := openOperatorDirectoryWithRoot(path, opener); err == nil {
				root.Close()
				t.Fatal("root branch accepted Users read ACE")
			}
			if calls != 2 {
				t.Fatal("root branch did not use injected directory")
			}
		})
	}
}
