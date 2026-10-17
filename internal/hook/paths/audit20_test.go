package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAudit20AWSConfig(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	for _, name := range []string{"config", "credentials"} {
		file := filepath.Join(home, ".aws", name)
		if err := os.WriteFile(file, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		if !Protected(file, root, "", home) || !LexicalProtected(file, root, home) || !TreeProtected(filepath.Dir(file), root, home) {
			t.Errorf("AWS %s was not protected", name)
		}
	}
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "custom.ini")
			if !Protected("custom.ini", root, "", home) || !ConfiguredTreeProtected(root, root, home, "") {
				t.Error("literal inherited AWS config path was not protected")
			}
			if Protected("public.ini", root, "", home) || ConfiguredTreeProtected(filepath.Join(root, "public"), root, home, "") {
				t.Error("unrelated file or scope was classified as AWS config")
			}
		})
	}
}

// The injected resolver models Windows EvalSymlinks expanding an existing 8.3
// prefix. It runs on every OS, including for configured files not created yet.
func TestAudit20CanonicalExisting(t *testing.T) {
	root := t.TempDir()
	short, long := filepath.Join(root, "SHORT~1"), filepath.Join(root, "long-name")
	for _, suffix := range []string{"", "credential.cfg", filepath.Join("missing", "credential.cfg")} {
		name := filepath.Join(short, suffix)
		got, err := canonicalExisting(name, func(candidate string) (string, error) {
			if candidate == short {
				return long, nil
			}
			return "", os.ErrNotExist
		})
		if want := filepath.Join(long, suffix); err != nil || got != want {
			t.Errorf("suffix=%q got=%q error=%v, want %q", suffix, got, err, want)
		}
	}
	if _, err := canonicalExisting(short, func(string) (string, error) { return "", os.ErrPermission }); err != os.ErrPermission {
		t.Errorf("resolution error was hidden: %v", err)
	}
}
