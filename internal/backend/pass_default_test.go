//go:build !secretstub

package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPassDefaultBuildIgnoresStubEnvironment(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("PASSWORD_STORE_DIR", filepath.Join(root, "missing"))
	t.Setenv("SECRET_BACKEND_STUB_DIR", root)
	provider, _, _, err := Dispatch("pass:team")
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("Windows pass dispatch enabled")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provider.(*passProvider); !ok {
		t.Fatal("default pass dispatch selected directory stub")
	}
}

func TestPassIsolatedProcessEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix synthetic process")
	}
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("PASSWORD_STORE_DIR", root)
	t.Setenv("TMPDIR", root)
	marker := filepath.Join(root, "startup")
	startup := filepath.Join(root, "startup.sh")
	if err := os.WriteFile(startup, []byte(": > '"+marker+"'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", startup)
	t.Setenv("ENV", startup)
	t.Setenv("PATH", "."+string(os.PathListSeparator)+root+string(os.PathListSeparator))
	t.Setenv("PASSWORD_STORE_GPG_OPTS", "--output synthetic-artifact")
	selected, err := newPass()
	if err != nil {
		t.Fatal(err)
	}
	p := selected.(*passProvider)
	if p.searchPath != root {
		t.Fatal("relative PATH components survived")
	}
	out, diagnostic, err := runProviderEnv("/bin/bash", []string{"-c", `test -z "${BASH_ENV+x}${ENV+x}${PASSWORD_STORE_KEY+x}" && test "$PASSWORD_STORE_GPG_OPTS" = '--no-options --batch --no-tty --pinentry-mode error --status-fd 2 --logger-fd 2' && printf synthetic-ok`}, nil, p.environment)
	if err != nil || string(out) != "synthetic-ok" || len(diagnostic) != 0 {
		t.Fatal("provider process inherited unsafe environment")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("shell startup executed")
	}
}
