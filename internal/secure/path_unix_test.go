//go:build !windows

package secure

import "testing"

func TestUnixPathContractUnchanged(t *testing.T) {
	for _, name := range []string{"", `C:relative`, `file:stream`, `back\slash`, "raw\xffname"} {
		if ValidateStorePath(name) != nil || ExplicitStorePath(name) {
			t.Fatalf("Unix filename contract changed for %q", name)
		}
	}
	for _, name := range []string{"link/../file", "/absolute", "./relative"} {
		if !ExplicitStorePath(name) {
			t.Fatalf("Unix explicit path contract changed for %q", name)
		}
	}
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "/not-the-unix-home")
	if home, err := UserHome(); err != nil || home != "" {
		t.Fatal("unset Unix HOME contract changed")
	}
	t.Setenv("HOME", "/explicit")
	if home, err := UserHome(); err != nil || home != "/explicit" {
		t.Fatal("explicit Unix HOME contract changed")
	}
}
