package store

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPassManifestPathsAndGrammar(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct{ ref, suffix string }{
		{"keychain:team", "team.keys"}, {"libsecret:team", "team.keys"}, {"pass:team", "team.pass-keys"},
	} {
		path, err := ManifestPath(dir, test.ref)
		if err != nil || path != filepath.Join(dir, test.suffix) {
			t.Fatal("incorrect manifest namespace")
		}
	}
	for _, ref := range []string{"pass:", "pass:../team", "pass:a/b", "pass:-bad", "pass:a:b", "file:team", "unknown:team"} {
		if _, err := ManifestPath(dir, ref); err == nil {
			t.Fatal("invalid reference accepted")
		}
	}
	valid := "secret-manifest-v1\nbackend=pass\nTOKEN\tenv=prod\t0123456789abcdef0123456789abcdef\n"
	for _, test := range []struct {
		name, data, kind string
		valid            bool
	}{
		{"valid", valid, "pass", true},
		{"backend mismatch", valid, "libsecret", false},
		{"duplicate identity", valid + strings.SplitAfterN(valid, "\n", 3)[2], "pass", false},
		{"bad account", strings.ReplaceAll(valid, "0123456789abcdef0123456789abcdef", "invalid"), "pass", false},
		{"extra field", strings.TrimSuffix(valid, "\n") + "\tvalue\n", "pass", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseManifest([]byte(test.data), test.kind); (err == nil) != test.valid {
				t.Fatal("manifest validation differs")
			}
		})
	}
	records, err := ParseManifest([]byte(valid), "pass")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"libsecret", "pass"} {
		path, _ := ManifestPath(dir, kind+":team")
		data, err := EncodeManifest(records, kind)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadManifest(path, kind); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	path, _ := ManifestPath(dir, "pass:team")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path, "pass"); err == nil {
		t.Fatal("public inventory accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "team.keys"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(path, "pass"); err == nil {
		t.Fatal("aliased inventory accepted")
	}
}

// This invariant also holds while pass routing is inactive: reserved references
// must reject, never reach a plaintext file probe, until activation is complete.
func TestPassReservedReferenceNeverFallsBack(t *testing.T) {
	locator := Locator{IsFile: func(string) bool { t.Fatal("reserved pass reference probed a plaintext path"); return false }}
	for _, reference := range []string{"pass:team", "pass:", "pass:../team", "pass:team/sub"} {
		resolved, err := locator.Resolve(reference)
		if err == nil && resolved != reference {
			t.Fatal("reserved pass reference became a plaintext path")
		}
		if reference != "pass:team" && err == nil {
			t.Fatal("malformed pass reference accepted")
		}
	}
}
