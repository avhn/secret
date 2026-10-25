//go:build linux || darwin

package feature

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func TestOperatorPassIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_PASS") != "1" {
		t.Skip("isolated GitHub pass fixture not requested")
	}
	root := os.Getenv("SECRET_PASS_TEST_ROOT")
	if os.Getenv("GITHUB_ACTIONS") != "true" || !filepath.IsAbs(root) || os.Getenv("HOME") != filepath.Join(root, "home") || os.Getenv("PASSWORD_STORE_DIR") != filepath.Join(root, "passwords") {
		t.Fatal("required isolated pass setup missing")
	}
	dir := t.TempDir()
	ref := "pass:native-operator"
	operator := Operator{SecretsDir: dir, Confirm: func(OperatorResult) error { return nil }}
	source := filepath.Join(dir, "synthetic.env")
	if err := os.WriteFile(source, []byte("TOKEN=synthetic-native-operator\n"), 0600); err != nil {
		t.Fatal(err)
	}
	request := ImportRequest{Source: "dotenv:" + source, Target: ref}
	if _, err := operator.Import(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Import(context.Background(), request); err != secure.ErrConflict {
		t.Fatal("native identity collision accepted")
	}
	if _, err := operator.Export(context.Background(), ExportRequest{Source: ref, Target: "pass:native-export", OnConflict: "fail"}); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{ref, "pass:native-export"} {
		if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: target, Key: "TOKEN"}, func() ([]byte, error) { return []byte("synthetic-native-rotated"), nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRename, Reference: target, Key: "TOKEN", NewKey: "RENAMED"}, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionDelete, Reference: target, Key: "RENAMED"}, nil); err != nil {
			t.Fatal(err)
		}
		records, err := backend.ListNames(dir, target)
		if err != nil || len(records) != 0 {
			t.Fatal("native lifecycle inventory differs")
		}
		path, _ := store.ManifestPath(dir, target)
		if _, err := store.ReadRecovery(path, "pass"); !os.IsNotExist(err) {
			t.Fatal("successful native lifecycle left recovery")
		}
	}
	// Encryption to a protected key can succeed while readback cannot. The
	// transaction must retain intent and the previous manifest, not publish a link.
	locked := os.Getenv("SECRET_PASS_TEST_LOCKED_RECIPIENT")
	if locked == "" {
		t.Fatal("required locked recipient missing")
	}
	policy := filepath.Join(root, "passwords", ".gpg-id")
	original, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(policy, original, 0600)
	if err := os.WriteFile(policy, []byte(locked+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Import(context.Background(), ImportRequest{Source: "dotenv:" + source, Target: "pass:locked-operator"}); err != secure.ErrRecovery {
		t.Fatal("locked-key readback did not retain recovery")
	}
	path, _ := store.ManifestPath(dir, "pass:locked-operator")
	if _, err := store.ReadManifest(path, "pass"); !os.IsNotExist(err) {
		t.Fatal("unverified native value published")
	}
	if _, err := store.ReadRecovery(path, "pass"); err != nil {
		t.Fatal("native partial-write recovery missing")
	}
}
