package paths

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestWindowsStreamBase(t *testing.T) {
	for _, tc := range []struct{ name, volume, want string }{
		{".env:stream", "", ".env"},
		{".env::$DATA", "", ".env"},
		{"dir/.aws/credentials:stream", "", "dir/.aws/credentials"},
		{`C:\synthetic\.env::$DATA`, "C:", `C:\synthetic\.env`},
		{`\\?\C:\synthetic\.env:stream`, `\\?\C:`, `\\?\C:\synthetic\.env`},
		{`\\host\share\.env::$DATA`, `\\host\share`, `\\host\share\.env`},
		{"public.txt::$DATA", "", "public.txt"},
	} {
		if got := windowsStreamBase(tc.name, tc.volume); got != tc.want {
			t.Errorf("base(%q)=%q want %q", tc.name, got, tc.want)
		}
	}
}

func TestNativeStreamProtection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows alternate data streams")
	}
	root := t.TempDir()
	for _, name := range []string{".env:stream", ".env::$DATA", ".aws/credentials:stream", ".envrc:stream"} {
		if !Protected(name, root, "", root) || !Protected(filepath.Join(root, name), root, "", root) {
			t.Errorf("protected base lost for %q", name)
		}
	}
	if Protected("public.txt::$DATA", root, "", root) {
		t.Fatal("public stream treated as a protected base")
	}
}
