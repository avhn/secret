//go:build windows

package store

import "testing"

func TestWindowsDefaultsRejectAmbiguousOverrides(t *testing.T) {
	for _, overrides := range [][2]string{
		{`C:relative`, `C:\synthetic.env`},
		{`C:\synthetic`, `C:relative`},
		{`\\?\C:\synthetic`, `C:\synthetic.env`},
		{`C:\synthetic`, `C:\synthetic.env:stream`},
	} {
		loc := Locator{SecretsDir: overrides[0], SecretsEnv: overrides[1],
			IsFile: func(string) bool { t.Fatal("invalid default reached filesystem"); return false },
			Glob:   func(string) ([]string, error) { t.Fatal("invalid default reached glob"); return nil, nil },
		}
		if _, err := loc.Defaults(); err != ErrInvalidKeystoreName {
			t.Fatal("ambiguous default accepted")
		}
	}
}

func TestResolveWindowsNativePaths(t *testing.T) {
	loc := Locator{Home: `C:\profile`, IsFile: func(string) bool { return false }}
	for _, name := range []string{`C:\private\synthetic.secret`, `relative\synthetic.secret`, `\\server\share\synthetic.secret`, `C:\junction\..\synthetic.secret`, `file:C:\private\synthetic.secret`} {
		if got, err := loc.Resolve(name); err != nil || got != name {
			t.Errorf("native path changed: %q: %q, %v", name, got, err)
		}
	}
	loc.IsFile = func(string) bool {
		t.Fatal("invalid path reached filesystem observation")
		return false
	}
	for _, name := range []string{`C:relative`, `\rooted`, `file:\rooted`, `file:C:relative`, `file:C:\item:stream`, `C:\item:stream`, `\\?\C:\private`, `NUL`, `file:`} {
		if _, err := loc.Resolve(name); err != ErrInvalidKeystoreName {
			t.Errorf("ambiguous native reference accepted: %q", name)
		}
	}
}
