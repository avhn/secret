//go:build !secretstub

package backend

import (
	"path/filepath"
	"testing"
)

func TestDefaultBuildIgnoresStubEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECRET_BACKEND_STUB_DIR", filepath.Join(dir, "stub"))
	for _, ref := range []string{"keychain:demo", "libsecret:demo"} {
		p, _, _, err := Dispatch(ref)
		if err != nil {
			t.Fatal(err)
		}
		switch ref {
		case "keychain:demo":
			if _, ok := p.(keychain); !ok {
				t.Fatal("production keychain dispatch selected test provider")
			}
		case "libsecret:demo":
			if _, ok := p.(libsecret); !ok {
				t.Fatal("production libsecret dispatch selected test provider")
			}
		}
	}
}
