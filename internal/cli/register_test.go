package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/hook"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func registrationArgs() []string {
	return []string{"onepassword:test", "TOKEN", "--reference", "op://" + strings.Repeat("v", 26) + "/" + strings.Repeat("i", 26) + "/password", "--account", strings.Repeat("a", 26), "--auth", "service-account", "--label", "env=dev"}
}
func TestOnePasswordRegistrationChallenge(t *testing.T) {
	request, err := parseRegister(registrationArgs())
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := registrationChallenge(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{request.Target, request.Key, "labels=env=dev", request.Provider.Reference, request.Provider.AccountUUID, "auth=service-account"} {
		if !bytes.Contains(challenge, []byte(text)) {
			t.Fatal("challenge omitted binding")
		}
	}
	for _, answer := range [][]byte{secure.Clone(challenge), []byte("yes"), bytes.Replace(challenge, []byte("env=dev"), []byte("env=prod"), 1), bytes.Replace(challenge, []byte("/password"), []byte("/other"), 1)} {
		exact := bytes.Equal(answer, challenge)
		console := &fakeOperatorConsole{inputs: [][]byte{answer}}
		terminal := &OperatorTerminal{console: console}
		err := terminal.confirmRegistration(request)
		if (err == nil) != exact {
			t.Fatal("inexact consent accepted")
		}
		assertClearedOperatorBytes(t, answer)
	}
	request.Provider.Reference += "\nunsafe"
	console := &fakeOperatorConsole{}
	terminal := &OperatorTerminal{console: console}
	if terminal.confirmRegistration(request) != secure.ErrInvalidRequest || console.Len() != 0 || console.reads != 0 {
		t.Fatal("invalid metadata rendered")
	}
	if _, err := operatorChallenge(OperatorRequest{Action: store.ActionRegister, Target: "libsecret:test", Keys: []string{"TOKEN"}}); err != secure.ErrInvalidRequest {
		t.Fatal("registration widened writable operator acceptance")
	}
	for _, args := range [][]string{append(registrationArgs(), "--auth", "service-account"), {"onepassword:../bad", "TOKEN"}, append(registrationArgs(), "--value", "synthetic")} {
		if _, err := parseRegister(args); err == nil {
			t.Fatal("invalid registration accepted")
		}
	}
}
func TestOnePasswordCLIDisabledAndReadOnly(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "absent")
	t.Setenv("HOME", root)
	t.Setenv("SECRETS_DIR", directory)
	cases := [][]string{append([]string{"register"}, registrationArgs()...), {"show", "onepassword:test"}, {"show", "--format=json", "onepassword:test"}, {"run", "-f", "onepassword:test", "--", "never-start"}, {"stash", "onepassword:test", "TOKEN"}, {"import", "--from", "dotenv:" + filepath.Join(root, "missing"), "--into", "onepassword:test", "--audit-dir", filepath.Join(root, "audit")}, {"rotate", "onepassword:test", "TOKEN"}, {"export", "--from", "onepassword:test", "--to", "libsecret:dest", "--on-conflict=fail"}}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if status := Main(args, nil, &out, &errOut); status == 0 {
			t.Fatal("inactive operation succeeded")
		}
		if args[0] == "stash" || args[0] == "import" || args[0] == "rotate" || args[0] == "export" {
			if !strings.Contains(errOut.String(), backend.ErrReadOnly.Error()) {
				t.Fatalf("lost read-only error for %s", args[0])
			}
		}
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("disabled operation created files")
	}
}

type onePasswordLaunchProvider struct {
	values map[string][]byte
	owned  [][]byte
	calls  int
	fail   int
}

func (p *onePasswordLaunchProvider) Get(_, id string) ([]byte, error) {
	p.calls++
	if p.calls == p.fail {
		return nil, errors.New("SYNTHETIC_PROVIDER_STDERR")
	}
	value := secure.Clone(p.values[id])
	p.owned = append(p.owned, value)
	return value, nil
}
func (*onePasswordLaunchProvider) Put(string, string, string, []byte) error {
	return backend.ErrReadOnly
}
func (*onePasswordLaunchProvider) Delete(string, string) error { return backend.ErrReadOnly }
func TestOnePasswordLaunchAllRecords(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix supervisor")
	}
	a, b, c := strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)
	records := []store.ManifestRecord{{Key: "TOKEN", Labels: map[string]string{}, Account: a}, {Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: b}, {Key: "OTHER", Labels: map[string]string{}, Account: c}}
	for _, fail := range []int{0, 2} {
		t.Run(map[bool]string{true: "failure", false: "success"}[fail != 0], func(t *testing.T) {
			provider := &onePasswordLaunchProvider{values: map[string][]byte{a: []byte("synthetic-selected"), b: []byte("synthetic-unselected"), c: []byte("synthetic-other")}, fail: fail}
			var out, errOut bytes.Buffer
			command := command{in: os.Stdin, out: &out, errOut: &errOut, dir: t.TempDir(), openRead: func(ctx context.Context, dir, reference string) ([]store.ManifestRecord, backend.Provider, string, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("no shared invocation budget")
				}
				return records, provider, "secret/test", nil
			}}
			t.Setenv("OTHER", "ambient-must-disappear")
			status := command.launch("run", []string{"-f", "onepassword:test", "--key", "TOKEN", "--", "sh", "-c", `test -z "${OTHER+x}" || exit 9; printf synthetic-; printf selected; printf ' synthetic-unselected'; printf synthetic- >&2; printf other >&2`})
			if fail == 0 {
				if status != 0 || out.String() != "<redacted> <redacted>" || errOut.String() != "<redacted>" || provider.calls != 3 {
					t.Fatalf("status=%d calls=%d", status, provider.calls)
				}
			} else if status == 0 || out.Len() != 0 || bytes.Contains(errOut.Bytes(), []byte("SYNTHETIC_PROVIDER_STDERR")) {
				t.Fatal("failure started child or leaked provider text")
			}
			for _, value := range provider.owned {
				assertClearedOperatorBytes(t, value)
			}
		})
	}
}
func TestOnePasswordMultiStoreFailureClears(t *testing.T) {
	a := strings.Repeat("a", 32)
	provider := &onePasswordLaunchProvider{values: map[string][]byte{a: []byte("synthetic-earlier")}}
	count := 0
	c := command{openRead: func(context.Context, string, string) ([]store.ManifestRecord, backend.Provider, string, error) {
		count++
		if count == 2 {
			return nil, nil, "", backend.ErrUnsupported
		}
		return []store.ManifestRecord{{Key: "TOKEN", Account: a}}, provider, "secret/test", nil
	}}
	if _, _, _, err := c.prepareLaunch(launchOptions{files: []string{"onepassword:first", "onepassword:second"}, selectors: store.Selectors{}}); err == nil {
		t.Fatal("failed store ignored")
	}
	for _, value := range provider.owned {
		assertClearedOperatorBytes(t, value)
	}
}
func TestOnePasswordMixedBashDiscovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash discovery")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "stores")
	if os.Mkdir(dir, 0700) != nil {
		t.Fatal("mkdir")
	}
	if err := os.WriteFile(filepath.Join(dir, "file.secret"), []byte("TOKEN=synthetic-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	v1, _ := store.EncodeManifest([]store.ManifestRecord{{Key: "V1", Account: strings.Repeat("a", 32)}}, "libsecret")
	os.WriteFile(filepath.Join(dir, "legacy.keys"), v1, 0600)
	request, _ := parseRegister(registrationArgs())
	v2, _ := store.EncodeManifestV2([]store.ManifestV2Record{{Key: request.Key, Labels: request.Labels, ID: strings.Repeat("b", 32), Provider: request.Provider}}, "onepassword")
	os.WriteFile(filepath.Join(dir, "test.onepassword-keys"), v2, 0600)
	cmd := exec.Command("bash", "../../bin/secret", "list")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "SECRETS_DIR=" + dir, "SECRETS_ENV=" + filepath.Join(root, "missing")}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Bash discovery: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("libsecret:legacy")) || !bytes.Contains(output, []byte("file.secret")) || bytes.Contains(output, []byte("onepassword")) {
		t.Fatal("Bash discovery changed")
	}
	loc := store.Locator{SecretsDir: dir, Home: root, IsFile: func(path string) bool { info, err := os.Stat(path); return err == nil && info.Mode().IsRegular() }, Glob: filepath.Glob}
	c := command{dir: dir, loc: loc, onePasswordTest: true}
	refs, err := c.defaults()
	if err != nil || !strings.Contains(strings.Join(refs, ","), "onepassword:test") {
		t.Fatal("test discovery missing v2")
	}
}
func TestOnePasswordGuardRegression(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell adapters")
	}
	for _, host := range []string{"claude", "codex"} {
		for _, text := range []string{"op read op://synthetic/vault/password", "command op read op://synthetic/vault/password", "'op' 'read' op://synthetic/vault/password", "op item get synthetic --reveal", "op item get synthetic --fields password", "secret register onepassword:test TOKEN --reference op://synthetic/vault/password --account synthetic --auth service-account"} {
			tool := "Bash"
			input := map[string]any{"command": text}
			payload, _ := json.Marshal(map[string]any{"tool_name": tool, "cwd": t.TempDir(), "tool_input": input})
			var out bytes.Buffer
			if err := hook.Decide(host, bytes.NewReader(payload), &out); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(out.Bytes(), []byte(`"permissionDecision":"deny"`)) {
				t.Fatalf("%s allowed %s", host, text)
			}
		}
	}
}

func TestOnePasswordSelectedLookup(t *testing.T) {
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	provider := &onePasswordLaunchProvider{values: map[string][]byte{a: []byte("synthetic-selected"), b: []byte("synthetic-unselected")}}
	c := command{openRead: func(context.Context, string, string) ([]store.ManifestRecord, backend.Provider, string, error) {
		return []store.ManifestRecord{{Key: "TOKEN", Account: a}, {Key: "OTHER", Account: b}}, provider, "secret/test", nil
	}}
	value, err := c.lookup("onepassword:test", "TOKEN", nil)
	defer secure.Clear(value)
	if err != nil || provider.calls != 1 || !bytes.Equal(value, []byte("synthetic-selected")) {
		t.Fatal("lookup fetched more than selected record")
	}
}
