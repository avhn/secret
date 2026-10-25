//go:build linux || darwin

package backend

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// The Python driver owns keys, agents and all directories. A required gate never
// skips missing setup, and local test runs never initialize or contact GnuPG.
func passIntegrationRoot(t *testing.T) string {
	t.Helper()
	if os.Getenv("SECRET_REQUIRE_PASS") != "1" {
		t.Skip("isolated GitHub pass fixture not requested")
	}
	root := os.Getenv("SECRET_PASS_TEST_ROOT")
	if os.Getenv("GITHUB_ACTIONS") != "true" || !filepath.IsAbs(root) || os.Getenv("HOME") != filepath.Join(root, "home") {
		t.Fatal("required isolated pass setup missing")
	}
	for _, name := range []string{"home", "gpg", "passwords", "tmp"} {
		info, err := os.Lstat(filepath.Join(root, name))
		if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
			t.Fatal("required private pass fixture missing")
		}
	}
	if !passSigningKeys.MatchString(os.Getenv("SECRET_PASS_TEST_RECIPIENT")) {
		t.Fatal("required synthetic recipient missing")
	}
	return root
}
func TestPassIntegration(t *testing.T) {
	root := passIntegrationRoot(t)
	fixture := func(t *testing.T) *passProvider {
		t.Helper()
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".gpg-id"), []byte(os.Getenv("SECRET_PASS_TEST_RECIPIENT")+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PASSWORD_STORE_DIR", dir)
		selected, err := newPass()
		if err != nil {
			t.Fatal(err)
		}
		return selected.(*passProvider)
	}
	t.Run("bytes and private modes", func(t *testing.T) {
		for _, value := range [][]byte{[]byte("synthetic-native-é-$TOKEN"), {0xff, 'x'}, bytes.Repeat([]byte{'x'}, passValueLimit)} {
			p := fixture(t)
			account, err := store.NewAccount()
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Put("secret/native", account, "", value); err != nil {
				t.Fatal("native encryption failed")
			}
			got, err := p.Get("secret/native", account)
			if err != nil || !bytes.Equal(got, value) {
				t.Fatal("native exact readback failed")
			}
			secure.Clear(got)
			info, err := os.Stat(filepath.Join(p.directory, "secret/native", account, "value.gpg"))
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatal("ciphertext not private")
			}
			if err := p.Delete("secret/native", account); err != nil {
				t.Fatal("native exact deletion failed")
			}
		}
	})
	for _, kind := range []string{"missing store", "missing gpg-id", "missing gpg", "missing recipient", "missing secret key", "locked key", "corrupt ciphertext", "permissions", "signature missing", "signature invalid", "signature valid", "gpg config isolation", "rm ignored"} {
		t.Run(kind, func(t *testing.T) {
			p := fixture(t)
			value := []byte("synthetic-native-value")
			account := passTestAccount
			switch kind {
			case "missing gpg":
				tools := t.TempDir()
				for _, tool := range []string{"gpg", "gpg2"} {
					if err := os.WriteFile(filepath.Join(tools, tool), []byte("#!/bin/sh\nexit 127\n"), 0700); err != nil {
						t.Fatal(err)
					}
				}
				for i, item := range p.environment {
					if strings.HasPrefix(item, "PATH=") {
						p.environment[i] = "PATH=" + tools + string(os.PathListSeparator) + strings.TrimPrefix(item, "PATH=")
					}
				}
			case "missing store":
				p.directory = filepath.Join(p.directory, "missing")
			case "missing gpg-id":
				if err := os.Remove(filepath.Join(p.directory, ".gpg-id")); err != nil {
					t.Fatal(err)
				}
			case "missing recipient":
				if err := os.WriteFile(filepath.Join(p.directory, ".gpg-id"), []byte(strings.Repeat("F", 40)+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked key":
				if err := os.WriteFile(filepath.Join(p.directory, ".gpg-id"), []byte(os.Getenv("SECRET_PASS_TEST_LOCKED_RECIPIENT")+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(kind, "signature ") {
				p.environment = append(p.environment, "PASSWORD_STORE_SIGNING_KEY="+os.Getenv("SECRET_PASS_TEST_RECIPIENT"))
				if kind != "signature missing" {
					body := []byte("synthetic-invalid-signature")
					if kind == "signature valid" {
						var err error
						body, err = os.ReadFile(filepath.Join(root, "recipient.sig"))
						if err != nil {
							t.Fatal(err)
						}
					}
					if err := os.WriteFile(filepath.Join(p.directory, ".gpg-id.sig"), body, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "gpg config isolation" {
				config := []byte("output " + filepath.Join(root, "plaintext-artifact") + "\nstatus-fd 1\n")
				path := filepath.Join(root, "gpg", "gpg.conf")
				if err := os.WriteFile(path, config, 0600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(path)
			}
			err := p.Put("secret/native", account, "", value)
			if kind == "missing store" || kind == "missing gpg-id" || kind == "missing gpg" || kind == "missing recipient" || kind == "signature missing" || kind == "signature invalid" {
				if err == nil {
					t.Fatal("unsafe encryption accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("native insert failed")
			}
			path := filepath.Join(p.directory, "secret/native", account, "value.gpg")
			switch kind {
			case "missing secret key":
				for i, item := range p.environment {
					if strings.HasPrefix(item, "GNUPGHOME=") {
						p.environment[i] = "GNUPGHOME=" + filepath.Join(root, "public-gpg")
					}
				}
			case "corrupt ciphertext":
				if err := os.WriteFile(path, []byte("synthetic corrupt ciphertext"), 0600); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(filepath.Dir(path), 0000); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(filepath.Dir(path), 0700)
			case "rm ignored":
				tools := t.TempDir()
				if err := os.WriteFile(filepath.Join(tools, "rm"), []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
					t.Fatal(err)
				}
				for i, item := range p.environment {
					if strings.HasPrefix(item, "PATH=") {
						p.environment[i] = "PATH=" + tools + string(os.PathListSeparator) + strings.TrimPrefix(item, "PATH=")
					}
				}
				if err := p.Delete("secret/native", account); err == nil {
					t.Fatal("native pass exit zero hid rm failure")
				}
				return
			}
			got, err := p.Get("secret/native", account)
			defer secure.Clear(got)
			reject := kind == "locked key" || kind == "missing secret key" || kind == "corrupt ciphertext" || kind == "permissions"
			if (err != nil) != reject || (!reject && !bytes.Equal(got, value)) {
				t.Fatal("native failure/readback contract differs")
			}
			for _, name := range []string{"plaintext-artifact", "pinentry-launched"} {
				if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
					t.Fatal("GPG configuration or pinentry escaped capture")
				}
			}
		})
	}
}
