//go:build windows

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// os.Symlink rewrites forward slashes on Windows. Preserve literal link text
// so refs/ and refs\ are genuinely different validate_headref fixtures.
func gitHeadSymlink(target, name string) error {
	link, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	text, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	const allowUnprivilegedCreate = 0x2 // SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
	return windows.CreateSymbolicLink(link, text, allowUnprivilegedCreate)
}

func TestWindowsGitHeadSignatures(t *testing.T) {
	testGitHeadSignatures(t, true, func(t *testing.T, root, dir string, want bool) {
		t.Helper()
		if got := nativeGitDirectory(dir); got != want {
			t.Errorf("nativeGitDirectory = %v, want %v", got, want)
		}
		for _, name := range []string{"config", "hooks/new"} {
			target := filepath.Join(dir, filepath.FromSlash(name))
			if got := nativeGitProtected(target, root, "", root); got != want {
				t.Errorf("nativeGitProtected(%q) = %v, want %v", name, got, want)
			}
			if got := FileConfigWriteProtected(target, root, "", root, "", ""); got != want {
				t.Errorf("FileConfigWriteProtected(%q) = %v, want %v", name, got, want)
			}
		}
	})
}

func TestWindowsGitHeadJunctionControl(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"metadata", "metadata/objects", "metadata/refs", "public"} {
		if err := os.Mkdir(filepath.Join(root, filepath.FromSlash(name)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	head := filepath.Join(root, "metadata", "HEAD")
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", head, filepath.Join(root, "public")).CombinedOutput(); err != nil {
		t.Fatalf("required HEAD junction fixture: %v (%s)", err, output)
	}
	if gitHeadSignature(head) || nativeGitDirectory(filepath.Dir(head)) {
		t.Fatal("junction HEAD established a Git signature")
	}
	if FileConfigWriteProtected(filepath.Join(filepath.Dir(head), "config"), root, "", root, "", "") {
		t.Fatal("junction HEAD denied a public config write")
	}
}
