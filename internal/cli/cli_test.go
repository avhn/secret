package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestHumanBoundary(t *testing.T) {
	home := testutil.TempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", filepath.Join(home, "stores"))
	t.Setenv("SECRETS_ENV", filepath.Join(home, "fallback.store"))
	for _, tt := range []struct {
		name          string
		args          []string
		input, stderr string
		status        int
	}{
		{"get refuses before missing store", []string{"get", "does-not-exist.store", "TOKEN"}, "", "secret: get is human-terminal-only; use show or run instead\n", 1},
		{"stash rejects invalid bytes", []string{"stash", "file:" + filepath.Join(home, "sample.store"), "TOKEN"}, "synth\x00etic\n", "secret: invalid value (empty, whitespace, quotes, newline, NUL, or CR)\n", 1},
		{"clip validates seconds", []string{"clip", "does-not-exist.store", "TOKEN", "not-a-number"}, "", "secret: SECONDS must be a number\n", 1},
		{"show option needs argument", []string{"show", "--env"}, "", "secret: option needs an argument\n", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && tt.args[0] == "stash" {
				// Native stash rejects redirected input before reading any bytes.
				tt.stderr = "secret: " + secure.ErrTerminalRequired.Error() + "\n"
			}
			f, err := os.CreateTemp(home, "stdin-*")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(f.Name())
			defer f.Close()
			if _, err = f.WriteString(tt.input); err != nil {
				t.Fatal(err)
			}
			if _, err = f.Seek(0, 0); err != nil {
				t.Fatal(err)
			}
			var out, errOut strings.Builder
			got := Main(tt.args, f, &out, &errOut)
			if got != tt.status || out.Len() != 0 || errOut.String() != tt.stderr {
				t.Errorf("status %d stdout %q stderr %q, want %d empty %q", got, out.String(), errOut.String(), tt.status, tt.stderr)
			}
		})
	}
}

func TestManifestInventorySelection(t *testing.T) {
	home := testutil.TempDir(t)
	dir := filepath.Join(home, "stores")
	if err := testutil.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", dir)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "fallback.store"))
	manifest := "secret-manifest-v1\nbackend=libsecret\nTOKEN\t\t0123456789abcdef0123456789abcdef\nTOKEN\tenv=prod\tfedcba9876543210fedcba9876543210\n"
	if err := testutil.WriteFile(filepath.Join(dir, "synthetic.keys"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
	c := command{dir: dir, loc: store.Locator{Home: home, SecretsDir: dir, SecretsEnv: filepath.Join(home, "fallback.store"), IsFile: func(p string) bool { info, err := os.Stat(p); return err == nil && info.Mode().IsRegular() }, Glob: filepath.Glob}}
	refs, err := c.defaults()
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0] != "libsecret:synthetic" {
		t.Fatalf("references: %q", refs)
	}
	for _, tt := range []struct {
		selectors store.Selectors
		want      string
	}{
		{store.Selectors{}, "  TOKEN=<stored>\n  TOKEN [env=prod]=<stored>\n"},
		{store.Selectors{"env": "prod"}, "  TOKEN [env=prod]=<stored>\n"},
		{store.Selectors{"env": "qa"}, "  TOKEN=<stored>\n"},
	} {
		lines, err := c.show(refs[0], tt.selectors)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(lines, ""); got != tt.want {
			t.Errorf("selection %v: got %q, want %q", tt.selectors, got, tt.want)
		}
	}
}

func TestListRejectsSymlinkManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	home := testutil.TempDir(t)
	dir := filepath.Join(home, "stores")
	if err := testutil.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "synthetic.store")
	if err := testutil.WriteFile(target, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "synthetic.keys")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	c := command{dir: dir}
	_, err := c.defaults()
	if err == nil {
		t.Error("symlink manifest accepted")
	}
}

func TestMissingOptionArgument(t *testing.T) {
	for _, args := range [][]string{{"show", "--env"}, {"stash", "--label"}, {"run", "--key"}, {"exec", "-f"}} {
		var out, errOut bytes.Buffer
		if status := Main(args, os.Stdin, &out, &errOut); status != 1 || errOut.String() != "secret: option needs an argument\n" {
			t.Errorf("%v: status %d stderr %q", args, status, errOut.String())
		}
	}
}
