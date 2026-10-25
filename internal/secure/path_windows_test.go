//go:build windows

package secure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWindowsStorePaths(t *testing.T) {
	for _, name := range []string{`C:\private\file.secret`, `c:/private/file.secret`, `\\server\share\file.secret`, `//server/share/file.secret`, `relative\file.secret`, `relative/file.secret`, `file.secret`, `..\file.secret`, `C:\junction\..\file.secret`} {
		if err := ValidateStorePath(name); err != nil {
			t.Errorf("valid path rejected: %q", name)
		}
	}
	for _, name := range []string{"", `C:relative`, `C:`, `\rooted`, `/rooted`, `\\?\C:\file`, `\\.\C:\file`, `\??\C:\file`, `C:\file:stream`, `file:stream`, `\\server`, `C:\NUL`, `C:\COM1.txt`, `C:\trailing.`, `C:\trailing `, "bad\x00name", "bad\nname", "bad\xffname", `C:\wild*`, `C:\wild?`, `1:\file`} {
		if err := ValidateStorePath(name); err != ErrPrivateFile {
			t.Errorf("ambiguous path accepted: %q", name)
		}
	}
}

func TestWindowsReservedStoreComponents(t *testing.T) {
	reserved := []string{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
	for _, prefix := range []string{"COM", "LPT"} {
		for _, digit := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"} {
			reserved = append(reserved, prefix+digit)
		}
	}
	for _, base := range reserved {
		for _, spelling := range []string{base, strings.ToLower(base)} {
			for _, suffix := range []string{"", ".txt", ".tar.gz", ".", " ", ".txt. ", " .txt"} {
				component := spelling + suffix
				for _, name := range []string{
					component,
					`C:\private\` + component,
					`C:\private\` + component + `\file.secret`,
					`relative/` + component + `/file.secret`,
					`\\server\share\` + component + `\file.secret`,
					`\\` + component + `\share\file.secret`,
					`\\server\` + component + `\file.secret`,
				} {
					if err := ValidateStorePath(name); err != ErrPrivateFile {
						t.Errorf("reserved component accepted: %q", name)
					}
				}
			}
		}
	}
	for _, component := range []string{"COM0", "COM10", "LPT0", "LPT10", "COMLPT1", "COM1extra", "LPT¹extra", "CONSOLE", "NULextra", "CONIN", "CONOUT", "config.txt"} {
		for _, name := range []string{component, `C:\private\` + component + `\file.secret`} {
			if err := ValidateStorePath(name); err != nil {
				t.Errorf("ordinary component rejected: %q", name)
			}
		}
	}
}

func TestWindowsUserHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", filepath.Join(t.TempDir(), "profile"))
	if home, err := UserHome(); err != nil || home != os.Getenv("USERPROFILE") {
		t.Fatal("native home fallback failed")
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "explicit"))
	if home, err := UserHome(); err != nil || home != os.Getenv("HOME") {
		t.Fatal("explicit HOME lost precedence")
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, err := UserHome(); err == nil {
		t.Fatal("missing native home accepted")
	}
}

func TestWindowsFinalPathUsesHandle(t *testing.T) {
	root := privateTestRoot(t)
	file, err := CreatePrivateFile(root, "identity")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	path, err := FinalPath(file)
	if err != nil || !strings.HasSuffix(strings.ToLower(path), `\identity`) {
		t.Fatal("native handle identity unavailable")
	}
	if _, err := FinalPath(nil); err != ErrPrivateFile {
		t.Fatal("nil identity handle accepted")
	}
}
