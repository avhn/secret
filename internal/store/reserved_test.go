package store

import "testing"

func TestWincredReservedBeforeFileFallback(t *testing.T) {
	locator := Locator{IsFile: func(string) bool { t.Fatal("reserved wincred reference probed plaintext"); return false }}
	for _, reference := range []string{"wincred:synthetic", "wincred:", "wincred:../synthetic", "wincred:synthetic:other"} {
		resolved, err := locator.Resolve(reference)
		if err == nil && resolved != reference {
			t.Fatal("reserved wincred reference became a file")
		}
		if reference != "wincred:synthetic" && err == nil {
			t.Fatal("malformed wincred reference accepted")
		}
	}
}
