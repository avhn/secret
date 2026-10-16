package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfiguredOversizedAliasSuffix(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	for _, suffix := range []string{strings.Repeat("public ", 50), filepath.Join(strings.Repeat("x", 300), "credential.cfg")} {
		for _, pair := range [][2]string{{alias, real}, {real, alias}} {
			configured := filepath.Join(pair[0], suffix)
			candidate := filepath.Join(pair[1], suffix)
			if !ConfiguredProtected(candidate, root, "", root, configured) {
				t.Errorf("configured alias lost for %q", suffix)
			}
			if !ConfiguredTreeProtected(pair[1], root, root, configured) {
				t.Errorf("configured subtree lost for %q", suffix)
			}
			if ConfiguredProtected(filepath.Join(pair[1], "public.txt"), root, "", root, configured) {
				t.Error("unrelated candidate matched configured name")
			}
			// Do not broaden physical's fail-closed metadata policy to make
			// configured-name comparison tolerate impossible components.
			if runtime.GOOS != "windows" {
				if _, err := physical(candidate); err == nil {
					t.Error("physical hid oversized-component error")
				}
			}
		}
	}
}

// No Windows path below reaches the filesystem or a network share. The injected
// resolver covers native drive, UNC, volume-relative and 8.3 spellings on Windows
// runners, and still checks the traversal bound on every other platform.
func TestCanonicalExistingTerminates(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../..", "/", `C:`, `C:.`, `C:..`, `C:..\..`, `C:missing\file`, `C:\`, `C:\SHORT~1\missing`, `\missing`, `\\server\share`, `\\server\share\missing`, `\\?\C:\missing`, `\\?\UNC\server\share\missing`} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := canonicalExisting(name, func(string) (string, error) {
				calls++
				if calls > 128 {
					t.Fatal("ancestor traversal exceeded budget")
				}
				return "", os.ErrNotExist
			})
			if err == nil || !errors.Is(err, os.ErrNotExist) && !errors.Is(err, fs.ErrInvalid) {
				t.Fatalf("unexpected resolution result: %v", err)
			}
		})
	}
	name := strings.Repeat("missing"+string(os.PathSeparator), 256) + "file"
	calls := 0
	if _, err := canonicalExisting(name, func(string) (string, error) {
		calls++
		return "", os.ErrNotExist
	}); !errors.Is(err, fs.ErrInvalid) || calls != 128 {
		t.Fatalf("deep path: calls=%d error=%v, want bounded failure", calls, err)
	}
}
