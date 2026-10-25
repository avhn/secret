package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestWincredInventoryAndNoFileFallback(t *testing.T) {
	dir := testutil.TempDir(t)
	ref := "wincred:synthetic"
	path, _ := store.ManifestPath(dir, ref)
	if err := store.UpdateManifest(path, "wincred", "TOKEN", nil, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(dir, "legacy.keys")
	if err := store.UpdateManifest(legacy, "libsecret", "LEGACY", nil, "fedcba9876543210fedcba9876543210"); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "plain.secret")
	if err := testutil.WriteFile(file, []byte("PLAIN=synthetic-value-sentinel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := command{dir: dir, loc: store.Locator{Home: dir, SecretsDir: dir, SecretsEnv: filepath.Join(dir, "missing.env"), IsFile: func(p string) bool { info, err := os.Stat(p); return err == nil && info.Mode().IsRegular() }, Glob: filepath.Glob}}
	resolved, err := c.loc.Resolve(ref)
	if err != nil || resolved != ref || !providerRef(resolved) {
		t.Fatal("wincred fell through to file resolution")
	}
	refs, err := c.defaults()
	if err != nil || !reflect.DeepEqual(refs, []string{"libsecret:legacy", ref, file}) {
		t.Fatal("mixed names-only inventory changed")
	}
	lines, err := c.show(ref, nil)
	if err != nil || strings.Join(lines, "") != "  TOKEN=<stored>\n" {
		t.Fatal("names-only show fetched values")
	}
	if runtime.GOOS != "windows" {
		if _, err := c.lookup(ref, "TOKEN", nil); !errors.Is(err, backend.ErrUnsupported) {
			t.Fatal("non-Windows value dispatch used a file fallback")
		}
	}
	for _, ref := range []string{"wincred:", "wincred:../synthetic", "wincred:synthetic/other"} {
		if _, err := c.loc.Resolve(ref); err == nil {
			t.Fatal("malformed wincred reference resolved")
		}
	}
	// Discovery requires the dedicated suffix and its matching backend header.
	if err := testutil.WriteFile(path, []byte("secret-manifest-v1\nbackend=libsecret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.defaults(); err == nil {
		t.Fatal("mismatched wincred discovery accepted")
	}
}
