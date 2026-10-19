package feature

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/avhn/secret/internal/secure"
)

func templateHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func TestTemplateBytes(t *testing.T) {
	selected := map[string][]byte{"KEY": []byte("synthetic{{OTHER}}"), "BINARY": {0, 0xff, '\n'}, "EMPTY": {}}
	for _, tc := range []struct {
		name, input string
		want        []byte
		bad         bool
	}{
		{"literal", "no placeholders", []byte("no placeholders"), false},
		{"exact repeated", "{{KEY}}/{{KEY}}", []byte("synthetic{{OTHER}}/synthetic{{OTHER}}"), false},
		{"binary", "{{BINARY}}", []byte{0, 0xff, '\n'}, false},
		{"empty", "x{{EMPTY}}y", []byte("xy"), false},
		{"missing", "{{MISSING}}", nil, true},
		{"unclosed", "{{KEY", nil, true},
		{"unopened", "KEY}}", nil, true},
		{"empty placeholder", "{{}}", nil, true},
		{"whitespace", "{{ KEY }}", nil, true},
		{"expression", "{{KEY | shell}}", nil, true},
		{"numeric", "{{2KEY}}", nil, true},
		{"nested", "{{{{KEY}}}}", nil, true},
		{"unmatched prefix", "}} {{KEY}}", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderTemplateBytes([]byte(tc.input), selected)
			defer secure.Clear(got)
			if tc.bad {
				if !errors.Is(err, ErrTemplate) || got != nil {
					t.Fatalf("expected fixed template error, got %v", err)
				}
			} else if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatal("template bytes did not match synthetic expectation")
			}
		})
	}
	for _, input := range [][]byte{bytes.Repeat([]byte("x"), MaxTemplateBytes+1), []byte("{{BIG}}{{BIG}}x")} {
		got, err := renderTemplateBytes(input, map[string][]byte{"BIG": make([]byte, maxRenderedBytes/2)})
		secure.Clear(got)
		if !errors.Is(err, ErrTemplate) {
			t.Fatal("oversized input or expansion was accepted")
		}
	}
}

func TestTemplatePrivateNamespace(t *testing.T) {
	home := templateHome(t)
	if runtime.GOOS == "windows" {
		_, err := RenderTemplate(home, []byte("literal"), nil)
		if !errors.Is(err, secure.ErrUnsupported) {
			t.Fatalf("Windows error: %v", err)
		}
		entries, err := os.ReadDir(home)
		if err != nil || len(entries) != 0 {
			t.Fatal("Windows refusal had filesystem side effects")
		}
		return
	}
	override := templateHome(t)
	t.Setenv("SECRETS_DIR", override)
	value := []byte("synthetic-value")
	rendered, err := RenderTemplate(home, []byte("prefix={{KEY}}"), map[string][]byte{"KEY": value})
	if err != nil {
		t.Fatal(err)
	}
	defer rendered.Close()
	if filepath.Base(rendered.Path()) != "payload" || filepath.Dir(filepath.Dir(rendered.Path())) != filepath.Join(home, ".secrets", ".rendered") {
		t.Fatal("render escaped the fixed namespace")
	}
	for path, mode := range map[string]os.FileMode{
		filepath.Join(home, ".secrets"):              0700,
		filepath.Join(home, ".secrets", ".rendered"): 0700,
		filepath.Dir(rendered.Path()):                0700,
		rendered.Path():                              0600,
	} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != mode || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("private mode mismatch: %v", err)
		}
	}
	data, err := os.ReadFile(rendered.Path())
	if err != nil || !bytes.Equal(data, []byte("prefix=synthetic-value")) {
		t.Fatal("synthetic payload mismatch")
	}
	secure.Clear(data)
	if !bytes.Equal(value, []byte("synthetic-value")) {
		t.Fatal("borrowed selected value was modified")
	}
	if err := rendered.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := rendered.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rendered.Close(); err != nil {
		t.Fatal("close must be idempotent")
	}
	if _, err := os.Lstat(filepath.Dir(rendered.Path())); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("random directory survived cleanup")
	}
	entries, err := os.ReadDir(override)
	if err != nil || len(entries) != 0 {
		t.Fatal("SECRETS_DIR override was used")
	}
}

func TestTemplateRejectsAncestors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix namespace validation")
	}
	for _, kind := range []string{"home alias", "home ancestor alias", "private alias", "rendered alias", "private mode", "rendered mode", "relative", "parent traversal"} {
		t.Run(kind, func(t *testing.T) {
			base := templateHome(t)
			home := filepath.Join(base, "home")
			if err := os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			private := filepath.Join(home, ".secrets")
			switch kind {
			case "home alias":
				alias := filepath.Join(base, "alias")
				if err := os.Symlink(home, alias); err != nil {
					t.Fatal(err)
				}
				home = alias
			case "home ancestor alias":
				alias := filepath.Join(base, "alias")
				if err := os.Symlink(base, alias); err != nil {
					t.Fatal(err)
				}
				home = filepath.Join(alias, "home")
			case "private alias":
				if err := os.Symlink(base, private); err != nil {
					t.Fatal(err)
				}
			case "rendered alias", "rendered mode":
				if err := os.Mkdir(private, 0700); err != nil {
					t.Fatal(err)
				}
				if kind == "rendered alias" {
					if err := os.Symlink(base, filepath.Join(private, ".rendered")); err != nil {
						t.Fatal(err)
					}
				} else if err := os.Mkdir(filepath.Join(private, ".rendered"), 0755); err != nil {
					t.Fatal(err)
				}
			case "private mode":
				if err := os.Mkdir(private, 0755); err != nil {
					t.Fatal(err)
				}
			case "relative":
				home = "relative"
			case "parent traversal":
				home += "/../home"
			}
			if r, err := RenderTemplate(home, []byte("literal"), nil); !errors.Is(err, ErrTemplatePath) {
				if r != nil {
					r.Close()
				}
				t.Fatalf("unsafe ancestor accepted: %v", err)
			}
		})
	}
}

func TestTemplateIdentityAndCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix anchored namespace")
	}
	for _, kind := range []string{"directory rename", "payload replacement", "private mode", "payload mode", "payload special mode"} {
		t.Run(kind, func(t *testing.T) {
			home := templateHome(t)
			r, err := RenderTemplate(home, []byte("synthetic"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			switch kind {
			case "directory rename":
				original := filepath.Join(home, ".secrets")
				if err := os.Rename(original, original+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original+"-moved", original); err != nil {
					t.Fatal(err)
				}
			case "payload replacement":
				if err := os.Rename(r.Path(), r.Path()+"-moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(r.Path(), []byte("public-replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			case "private mode":
				if err := os.Chmod(filepath.Dir(r.Path()), 0755); err != nil {
					t.Fatal(err)
				}
			case "payload mode":
				if err := os.Chmod(r.Path(), 0644); err != nil {
					t.Fatal(err)
				}
			case "payload special mode":
				if err := os.Chmod(r.Path(), 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(r.Validate(), ErrTemplatePath) {
				t.Fatal("identity or mode change not detected")
			}
			err = r.Close()
			if kind == "payload replacement" {
				if !errors.Is(err, ErrTemplateCleanup) {
					t.Fatal("replacement cleanup must report failure")
				}
				data, err := os.ReadFile(r.Path())
				if err != nil || !bytes.Equal(data, []byte("public-replacement")) {
					t.Fatal("cleanup removed unowned file")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTemplateConcurrent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix anchored namespace")
	}
	home := templateHome(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			r, err := RenderTemplate(home, []byte("{{KEY}}"), map[string][]byte{"KEY": []byte("synthetic")})
			if err != nil {
				t.Error(err)
				return
			}
			if err := r.Validate(); err != nil {
				t.Error(err)
			}
			if err := r.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	entries, err := os.ReadDir(filepath.Join(home, ".secrets", ".rendered"))
	if err != nil || len(entries) != 0 {
		t.Fatal("concurrent render left payloads behind")
	}
}
