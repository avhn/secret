package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAudit19CredentialPaths(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	for _, name := range []string{
		".kube/config", ".config/gcloud/application_default_credentials.json",
		".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db",
		".config/gcloud/legacy_credentials/synthetic/adc.json", ".vault-token",
		".terraform.d/credentials.tfrc.json", ".cargo/credentials.toml",
		".cargo/credentials", ".pgpass", ".yarnrc.yml",
	} {
		t.Run(name, func(t *testing.T) {
			target := filepath.Join(home, filepath.FromSlash(name))
			if !Protected(target, work, "", home) {
				t.Fatal("missing credential spelling was allowed")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			if !TreeProtected(home, work, home) {
				t.Fatal("credential tree was allowed")
			}
			if runtime.GOOS != "windows" {
				alias := filepath.Join(t.TempDir(), "alias.txt")
				if err := os.Symlink(target, alias); err != nil {
					t.Fatal(err)
				}
				if !Protected(alias, work, "", home) {
					t.Fatal("credential alias was allowed")
				}
			}
		})
	}
	if Protected(".yarnrc.yml", work, "", home) {
		t.Fatal("project Yarn config must remain readable")
	}
	for _, template := range []string{".env.example", ".env.sample", ".env.template", "service.env.example"} {
		if Protected(template, work, "", home) || !Protected(filepath.Join(home, ".secrets", template), work, "", home) {
			t.Fatalf("incorrect template scope for %s", template)
		}
	}
}

func TestAudit19ConfiguredKubernetesPaths(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	first, second := filepath.Join(root, "custom.json"), filepath.Join(root, "another.txt")
	t.Setenv("KUBECONFIG", strings.Join([]string{first, second}, string(os.PathListSeparator)))
	for _, name := range []string{first, second} {
		if !Protected(name, root, "", home) || !LexicalProtected(name, root, home) {
			t.Fatal("configured credential name was allowed")
		}
	}
	if Protected(filepath.Join(root, "public.json"), root, "", home) {
		t.Fatal("unconfigured public file was denied")
	}
	if !ConfiguredTreeProtected(root, root, home, first) || ConfiguredTreeProtected(filepath.Join(root, "src"), root, home, first) {
		t.Fatal("configured path containment proof is incorrect")
	}
	if runtime.GOOS == "windows" {
		if !Protected(strings.ToUpper(first)+"::$DATA", root, "", home) {
			t.Fatal("configured credential stream/case alias was allowed")
		}
	}
}
