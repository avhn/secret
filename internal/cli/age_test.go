package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func cliAgeFixture(t *testing.T) (command, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix age filesystem")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".secrets")
	keys := filepath.Join(dir, ".age-keys")
	if os.MkdirAll(keys, 0700) != nil {
		t.Fatal("mkdir")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("generate")
	}
	identity := filepath.Join(keys, "identity")
	recipients := filepath.Join(keys, "recipients")
	data := []byte(id.String() + "\n")
	defer secure.Clear(data)
	if os.WriteFile(identity, data, 0600) != nil || os.WriteFile(recipients, []byte(id.Recipient().String()+"\n"), 0600) != nil {
		t.Fatal("fixture")
	}
	config := backend.AgeConfig{Home: home, SecretsDir: dir, IdentityFile: identity}
	if err := config.Init("age:test", recipients); err != nil {
		t.Fatal(err)
	}
	if err := (backend.AgeTransaction{Config: config, Reference: "age:test"}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("SYNTHETIC-CLI-SELECTED")}, {Kind: store.MutationPut, Key: "HIDDEN", Labels: map[string]string{"env": "prod"}, Value: []byte("SYNTHETIC-CLI-UNSELECTED")}}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", dir)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "missing"))
	return command{dir: dir, ageIdentity: identity, loc: store.Locator{Home: home}, errOut: &bytes.Buffer{}}, "age:test"
}
func TestAgeCLIInterfaces(t *testing.T) {
	c, reference := cliAgeFixture(t)
	for _, args := range [][]string{{"show", reference}, {"show", "--format=json", reference}, {"list", "--backend", "age"}, {"list", "--backend=age", "--format=json"}, {"diff", "--format=json", reference}, {"completion", "--command", "run", "--flag=--key", "-f", reference}} {
		var out, diagnostic bytes.Buffer
		if status := Main(args, nil, &out, &diagnostic); status != 0 {
			t.Fatalf("%s: %s", args[0], diagnostic.String())
		}
		if bytes.Contains(out.Bytes(), []byte("SYNTHETIC-CLI")) || bytes.Contains(out.Bytes(), []byte("bytes)")) {
			t.Fatal("names leak")
		}
	}
	value, err := c.lookup(reference, "TOKEN", nil)
	defer secure.Clear(value)
	if err != nil || !bytes.Equal(value, []byte("SYNTHETIC-CLI-SELECTED")) {
		t.Fatal("age lookup")
	}
	var out, diagnostic bytes.Buffer
	if status := Main([]string{"list"}, nil, &out, &diagnostic); status != 0 || bytes.Contains(out.Bytes(), []byte("age:")) {
		t.Fatal("age default discovery")
	}
	path, _ := store.AgePath(c.dir, reference)
	if _, err := c.show("file:"+path, nil); err == nil {
		t.Fatal("envelope treated as plaintext")
	}
	if _, err := c.lookup("file:"+path, "TOKEN", nil); err == nil {
		t.Fatal("envelope plaintext lookup")
	}
}
func TestAgeLaunchLoadsEveryValueAndRejectsTemplate(t *testing.T) {
	c, reference := cliAgeFixture(t)
	t.Setenv("HIDDEN", "inherited-must-be-removed")
	env, all, _, err := c.prepareLaunch(launchOptions{files: []string{reference}, required: []string{"TOKEN"}, selectors: store.Selectors{}})
	defer func() {
		for _, value := range all {
			secure.Clear(value)
		}
	}()
	if err != nil || len(all) != 2 {
		t.Fatal("missing redaction values")
	}
	for _, entry := range env {
		if strings.HasPrefix(entry, "HIDDEN=") {
			t.Fatal("inherited unselected name")
		}
	}
	// Missing identity proves template rejection precedes identity access.
	c.ageIdentity = filepath.Join(c.loc.Home, ".secrets", ".age-keys", "missing")
	if _, _, _, err := c.prepareLaunch(launchOptions{files: []string{reference}, templateFile: "missing"}); err != secure.ErrInvalidRequest {
		t.Fatal("template reached decrypt")
	}
	if _, _, _, err := c.prepareLaunch(launchOptions{files: []string{reference}}); err != store.ErrAge {
		t.Fatal("missing identity not fixed failure")
	}
}
func TestAgeIdentityOptionScope(t *testing.T) {
	home := t.TempDir()
	identity := filepath.Join(home, ".secrets", ".age-keys", "identity")
	result, got, err := ageIdentityOption([]string{"-f", "age:test", "--age-identity", identity, "--", "child", "--age-identity", "child-data"}, home)
	if err != nil || got != identity || len(result) != 6 || result[4] != "--age-identity" {
		t.Fatal("option consumed child argv")
	}
	for _, args := range [][]string{{"--age-identity"}, {"--age-identity=relative"}, {"--age-identity", filepath.Join(home, "outside")}, {"--age-identity", identity, "--age-identity", identity}} {
		if _, _, err := ageIdentityOption(args, home); err == nil {
			t.Fatal("bad identity option")
		}
	}
}
func TestAgeCommandsTerminalGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", filepath.Join(home, "must-not-exist"))
	for _, sub := range []string{"age-init", "age-rekey"} {
		var out, diagnostic bytes.Buffer
		if Main([]string{sub, "--yes", "--age-identity", "relative"}, nil, &out, &diagnostic) != 1 {
			t.Fatal("nonterminal init")
		}
		want := secure.ErrTerminalRequired
		if diagnostic.String() != "secret: "+want.Error()+"\n" {
			t.Fatal("terminal gate ordering")
		}
	}
	if _, err := os.Stat(filepath.Join(home, "must-not-exist")); !os.IsNotExist(err) {
		t.Fatal("side effect before consent")
	}
}
