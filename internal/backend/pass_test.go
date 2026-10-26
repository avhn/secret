package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const passTestAccount = "0123456789abcdef0123456789abcdef"
const passTestVersion = "=                  v1.7.4                  =\n"

type passFake struct {
	directory                  string
	calls                      [][]string
	inputs, outputs            [][]byte
	fail, mismatch, keepDelete bool
}

func (f *passFake) run(_ string, args []string, input []byte, _ []string) ([]byte, []byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if args[0] == "version" {
		return []byte(passTestVersion), nil, nil
	}
	f.inputs = append(f.inputs, input)
	if f.fail {
		return []byte("synthetic-output-sentinel"), []byte("synthetic-diagnostic-sentinel"), errors.New("synthetic-failure-sentinel")
	}
	path := filepath.Join(f.directory, args[len(args)-1]+".gpg")
	var out []byte
	var err error
	switch args[0] {
	case "insert":
		err = os.WriteFile(path, input, 0600)
		out = []byte("synthetic-prompt-sentinel")
	case "show":
		out, err = os.ReadFile(path)
		if f.mismatch && len(out) > 0 {
			out[0] ^= 1
		}
	case "rm":
		if !f.keepDelete {
			err = os.Remove(path)
		}
	}
	diagnostic := []byte("synthetic-diagnostic-sentinel")
	f.outputs = append(f.outputs, out, diagnostic)
	return out, diagnostic, err
}
func passFixture(t *testing.T) (*passProvider, *passFake) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix provider transport")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gpg-id"), []byte("synthetic-recipient\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &passFake{directory: root}
	provider := &passProvider{directory: root, executable: "synthetic-pass", run: fake.run}
	provider.once.Do(func() {})
	return provider, fake
}
func passSeed(t *testing.T, p *passProvider) string {
	t.Helper()
	path := filepath.Join(p.directory, "secret/team", passTestAccount, "value.gpg")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("synthetic-value"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPassTransportAndClearing(t *testing.T) {
	p, f := passFixture(t)
	input := []byte("synthetic-é-$TOKEN-'\\")
	if err := p.Put("secret/team", passTestAccount, "ignored", input); err != nil {
		t.Fatal(err)
	}
	got, err := p.Get("secret/team", passTestAccount)
	if err != nil || !bytes.Equal(got, input) {
		t.Fatal("exact byte readback failed")
	}
	secure.Clear(got)
	if err := p.Delete("secret/team", passTestAccount); err != nil {
		t.Fatal(err)
	}
	entry := "secret/team/" + passTestAccount + "/value"
	wanted := [][]string{{"insert", "--multiline", "--", entry}, {"show", "--", entry}, {"rm", "--force", "--", entry}}
	if !reflect.DeepEqual(f.calls, wanted) {
		t.Fatal("transport argv changed")
	}
	for _, buffer := range append(f.inputs, f.outputs...) {
		if !bytes.Equal(buffer, make([]byte, len(buffer))) {
			t.Fatal("owned transport buffer retained")
		}
	}
	if !bytes.Equal(input, []byte("synthetic-é-$TOKEN-'\\")) {
		t.Fatal("borrowed value changed")
	}
}
func TestPassValueDomain(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		valid bool
	}{
		{"text", []byte("synthetic"), true}, {"utf8", []byte("é-文"), true}, {"invalid utf8", []byte{0xff, 'x'}, true},
		{"metacharacters", []byte("$x;`literal` \\ ' quote"), true}, {"limit", bytes.Repeat([]byte{'x'}, passValueLimit), true},
		{"oversize", bytes.Repeat([]byte{'x'}, passValueLimit+1), false}, {"empty", nil, false}, {"NUL", []byte("a\x00b"), false},
		{"CR", []byte("a\rb"), false}, {"LF", []byte("a\nb"), false}, {"terminal LF", []byte("a\n"), false},
		{"space", []byte(" a"), false}, {"tab", []byte("a\t"), false}, {"quotes", []byte("'a'"), false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			p, f := passFixture(t)
			err := p.Put("secret/team", passTestAccount, "", test.value)
			if (err == nil) != test.valid {
				t.Fatal("put value domain differs")
			}
			if !test.valid && len(f.calls) != 0 {
				t.Fatal("invalid value reached provider")
			}
			path := passSeed(t, p)
			if err := os.WriteFile(path, test.value, 0600); err != nil {
				t.Fatal(err)
			}
			value, err := p.Get("secret/team", passTestAccount)
			defer secure.Clear(value)
			if (err == nil) != test.valid {
				t.Fatal("read value domain differs")
			}
		})
	}
}
func TestPassCollisionAndExactReads(t *testing.T) {
	for _, kind := range []string{"account directory", "account file", "account symlink", "sibling ciphertext", "ancestor symlink", "public ancestor", "ciphertext symlink", "missing ciphertext", "ciphertext directory"} {
		t.Run(kind, func(t *testing.T) {
			p, f := passFixture(t)
			path := passSeed(t, p)
			account := filepath.Dir(path)
			switch kind {
			case "account file":
				os.Remove(path)
				os.Remove(account)
				os.WriteFile(account, []byte("foreign"), 0600)
			case "account symlink":
				os.Remove(path)
				os.Remove(account)
				os.Symlink(t.TempDir(), account)
			case "sibling ciphertext":
				os.Remove(path)
				os.Remove(account)
				os.WriteFile(account+".gpg", []byte("foreign"), 0600)
			case "ancestor symlink":
				os.Remove(path)
				os.Remove(account)
				os.Remove(filepath.Dir(account))
				os.Symlink(t.TempDir(), filepath.Dir(account))
			case "public ancestor":
				os.Chmod(filepath.Dir(account), 0755)
			case "ciphertext symlink":
				os.Remove(path)
				os.Symlink(filepath.Join(p.directory, ".gpg-id"), path)
			case "missing ciphertext":
				os.Remove(path)
			case "ciphertext directory":
				os.Remove(path)
				os.Mkdir(path, 0700)
			}
			if err := p.Put("secret/team", passTestAccount, "", []byte("new-synthetic")); err == nil {
				t.Fatal("collision accepted")
			}
			if len(f.calls) != 0 {
				t.Fatal("collision invoked provider")
			}
			if kind == "account directory" || kind == "sibling ciphertext" {
				return
			}
			if value, err := p.Get("secret/team", passTestAccount); err == nil {
				secure.Clear(value)
				t.Fatal("unsafe/missing exact entry read")
			}
			if err := p.Delete("secret/team", passTestAccount); err == nil {
				t.Fatal("unsafe/missing exact entry deleted")
			}
			if len(f.calls) != 0 {
				t.Fatal("unsafe path reached provider")
			}
		})
	}
}
func TestPassDeleteVerifiesAbsence(t *testing.T) {
	p, f := passFixture(t)
	path := passSeed(t, p)
	f.keepDelete = true
	if err := p.Delete("secret/team", passTestAccount); err == nil {
		t.Fatal("pass exit zero hid failed rm")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("foreign deletion occurred")
	}
}
func TestPassEnvironmentAndVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		if _, _, _, err := Dispatch("pass:team"); err == nil {
			t.Fatal("Windows pass enabled")
		}
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PASSWORD_STORE_DIR", filepath.Join(home, "synthetic-store"))
	t.Setenv("GNUPGHOME", filepath.Join(home, "gpg"))
	t.Setenv("TMPDIR", home)
	fingerprint := strings.Repeat("A", 40)
	for _, key := range []string{"BASH_ENV", "ENV", "SHELLOPTS", "GPG_TTY", "PASSWORD_STORE_KEY", "PASSWORD_STORE_GPG_OPTS", "PASSWORD_STORE_EXTENSIONS_DIR", "BASH_FUNC_fake%%"} {
		t.Setenv(key, "synthetic-injection")
	}
	for _, key := range []string{"", fingerprint, fingerprint + " " + strings.Repeat("B", 40), "lowercase", fingerprint + "\n"} {
		t.Setenv("PASSWORD_STORE_SIGNING_KEY", key)
		selected, err := newPass()
		valid := key == "" || passSigningKeys.MatchString(key)
		if (err == nil) != valid {
			t.Fatal("signing policy validation differs")
		}
		if !valid {
			continue
		}
		p := selected.(*passProvider)
		env := strings.Join(p.environment, "\n")
		if strings.Contains(env, "synthetic-injection") || !strings.Contains(env, "PASSWORD_STORE_GPG_OPTS="+passGPGOptions) {
			t.Fatal("unsafe provider environment")
		}
		if key != "" && !strings.Contains(env, "PASSWORD_STORE_SIGNING_KEY="+key) {
			t.Fatal("signing policy silently dropped")
		}
		t.Setenv("PASSWORD_STORE_DIR", filepath.Join(home, "changed"))
		if p.directory != filepath.Join(home, "synthetic-store") {
			t.Fatal("directory was not frozen")
		}
		t.Setenv("PASSWORD_STORE_DIR", filepath.Join(home, "synthetic-store"))
	}
	tools := t.TempDir()
	if err := os.WriteFile(filepath.Join(tools, "pass"), []byte("synthetic executable"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", tools)
	for _, version := range []string{passTestVersion, strings.ReplaceAll(passTestVersion, "1.7.4", "1.7.40"), "", strings.ReplaceAll(passTestVersion, "1.7.4", "1.7.3")} {
		p := &passProvider{searchPath: tools, run: func(_ string, args []string, _ []byte, _ []string) ([]byte, []byte, error) {
			if !reflect.DeepEqual(args, []string{"version"}) {
				t.Fatal("unexpected pin command")
			}
			return []byte(version), nil, nil
		}}
		if (p.initialize() == nil) != (version == passTestVersion) {
			t.Fatal("version pin differs")
		}
	}
	t.Setenv("PATH", t.TempDir())
	p := &passProvider{searchPath: os.Getenv("PATH"), run: func(string, []string, []byte, []string) ([]byte, []byte, error) {
		t.Fatal("missing executable ran")
		return nil, nil, nil
	}}
	if p.initialize() == nil {
		t.Fatal("missing pass accepted")
	}
}
func TestPassTransactionRecoveryAndFreshAccounts(t *testing.T) {
	for _, phase := range []string{"success", "intent", "prepare", "verify", "publish", "published", "cleanup", "complete", "encrypt", "mismatch", "rm zero"} {
		t.Run(phase, func(t *testing.T) {
			p, f := passFixture(t)
			dir := t.TempDir()
			ref := "pass:team"
			path, _ := store.ManifestPath(dir, ref)
			if err := Stash(dir, ref, "TOKEN", nil, []byte("prior\n"), p); err != nil {
				t.Fatal(err)
			}
			previous, err := store.ReadManifest(path, "pass")
			if err != nil {
				t.Fatal(err)
			}
			f.fail = phase == "encrypt"
			f.mismatch = phase == "mismatch"
			f.keepDelete = phase == "rm zero"
			tx := Transaction{SecretsDir: dir, Reference: ref, Provider: p}
			err = tx.apply([]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("rotated\n")}}, transactionSteps{checkpoint: func(at string, _ int) error {
				if at == phase {
					return errors.New("synthetic-fault")
				}
				return nil
			}})
			if phase == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("injected fault ignored")
			}
			records, readErr := store.ReadManifest(path, "pass")
			if readErr != nil || len(records) != 1 {
				t.Fatal("manifest lost")
			}
			published := phase == "success" || phase == "published" || phase == "cleanup" || phase == "complete" || phase == "rm zero"
			if (records[0].Account != previous[0].Account) != published {
				t.Fatal("wrong publication phase")
			}
			_, recoveryErr := store.ReadRecovery(path, "pass")
			tracked := phase != "success" && phase != "intent"
			if (recoveryErr == nil) != tracked {
				t.Fatal("recovery tracking differs")
			}
			if tracked && tx.Apply([]store.Mutation{{Kind: store.MutationPut, Key: "OTHER", Value: []byte("synthetic")}}) != secure.ErrRecovery {
				t.Fatal("pending recovery did not block")
			}
		})
	}
}
func TestPassConcurrentWritersAndReservations(t *testing.T) {
	t.Cleanup(store.SetLockWaitForTest(30 * time.Second))
	p, _ := passFixture(t)
	// Separate providers use the same root, just as independent processes do.
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			q := &passProvider{directory: p.directory, executable: "synthetic", run: func(_ string, args []string, input []byte, _ []string) ([]byte, []byte, error) {
				return nil, nil, os.WriteFile(filepath.Join(p.directory, args[len(args)-1]+".gpg"), input, 0600)
			}}
			q.once.Do(func() {})
			errs <- q.Put("secret/team", passTestAccount, "", []byte("synthetic"))
		}()
	}
	wait.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("reservation did not select one owner")
	}
	dir := t.TempDir()
	errs = make(chan error, 2)
	for _, key := range []string{"A", "B"} {
		wait.Add(1)
		go func(key string) {
			defer wait.Done()
			fake := &passFake{directory: p.directory}
			q := &passProvider{directory: p.directory, run: fake.run}
			q.once.Do(func() {})
			if key == "A" {
				errs <- Stash(dir, "pass:team", key, nil, []byte("synthetic"), q)
			} else {
				errs <- (Transaction{SecretsDir: dir, Reference: "pass:team", Provider: q, FailOnConflict: true}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: key, Value: []byte("synthetic")}})
			}
		}(key)
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	path, _ := store.ManifestPath(dir, "pass:team")
	records, err := store.ReadManifest(path, "pass")
	if err != nil || len(records) != 2 {
		t.Fatal("concurrent update lost")
	}
}

func TestPassDeleteRejectsUncertainAbsence(t *testing.T) {
	p, f := passFixture(t)
	passSeed(t, p)
	p.run = func(name string, args []string, input []byte, env []string) ([]byte, []byte, error) {
		out, diagnostic, err := f.run(name, args, input, env)
		if args[0] == "rm" {
			account := filepath.Join(p.directory, "secret/team", passTestAccount)
			if err := os.Rename(account, account+"-moved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(t.TempDir(), account); err != nil {
				t.Fatal(err)
			}
		}
		return out, diagnostic, err
	}
	if p.Delete("secret/team", passTestAccount) == nil {
		t.Fatal("aliased ancestor treated as certain absence")
	}
}

func TestPassRootAliasesAndInitialization(t *testing.T) {
	for _, kind := range []string{"alias", "alias with slash", "public root", "missing policy", "policy alias", "policy directory"} {
		t.Run(kind, func(t *testing.T) {
			p, f := passFixture(t)
			root := p.directory
			switch kind {
			case "alias", "alias with slash":
				link := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", t.TempDir())
				if kind == "alias with slash" {
					link += string(filepath.Separator)
				}
				t.Setenv("PASSWORD_STORE_DIR", link)
				selected, err := newPass()
				if err != nil {
					t.Fatal(err)
				}
				p = selected.(*passProvider)
				p.run = f.run
			case "public root":
				if err := os.Chmod(root, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing policy":
				if err := os.Remove(filepath.Join(root, ".gpg-id")); err != nil {
					t.Fatal(err)
				}
			case "policy alias":
				if err := os.Remove(filepath.Join(root, ".gpg-id")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("missing", filepath.Join(root, ".gpg-id")); err != nil {
					t.Fatal(err)
				}
			case "policy directory":
				if err := os.Remove(filepath.Join(root, ".gpg-id")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Join(root, ".gpg-id"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if p.Put("secret/team", passTestAccount, "", []byte("synthetic")) == nil {
				t.Fatal("unsafe/uninitialized root accepted")
			}
			if len(f.calls) != 0 {
				t.Fatal("unsafe root reached executable")
			}
		})
	}
}

func TestPassFailureOutputIsCleared(t *testing.T) {
	p, _ := passFixture(t)
	passSeed(t, p)
	out := []byte("synthetic-private-output-sentinel")
	diagnostic := []byte("synthetic-private-diagnostic-sentinel")
	p.run = func(string, []string, []byte, []string) ([]byte, []byte, error) {
		return out, diagnostic, errors.New("synthetic-private-error-sentinel")
	}
	value, err := p.Get("secret/team", passTestAccount)
	if err == nil || len(value) != 0 || strings.Contains(err.Error(), "sentinel") {
		t.Fatal("failed output escaped fixed error")
	}
	for _, buffer := range [][]byte{out, diagnostic} {
		if !bytes.Equal(buffer, make([]byte, len(buffer))) {
			t.Fatal("failed output retained")
		}
	}
}
