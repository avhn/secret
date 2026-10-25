//go:build agefixture

// Synthetic per-test key generation for test-age.py. Not part of the CLI.
package main

import (
	"os"
	"path/filepath"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
)

func main() {
	if len(os.Args) != 3 || (os.Args[2] != "primary" && os.Args[2] != "rotated") {
		os.Exit(2)
	}
	root := os.Args[1]
	name := os.Args[2]
	if !filepath.IsAbs(root) {
		os.Exit(2)
	}
	keys := filepath.Join(root, ".secrets", ".age-keys")
	if os.MkdirAll(keys, 0700) != nil {
		os.Exit(1)
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		os.Exit(1)
	}
	data := []byte(identity.String() + "\n")
	err = os.WriteFile(filepath.Join(keys, name+".identity"), data, 0600)
	secure.Clear(data)
	if err != nil {
		os.Exit(1)
	}
	if os.WriteFile(filepath.Join(keys, name+".recipients"), []byte(identity.Recipient().String()+"\n"), 0600) != nil {
		os.Exit(1)
	}
}
