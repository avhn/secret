package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func passCLI(t *testing.T, args []string, input []byte) (int, string, string) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(input); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	status := Main(args, file, &out, &diagnostic)
	return status, out.String(), diagnostic.String()
}
func TestPassDiscoveryAndNoFileFallback(t *testing.T) {
	originalPath := os.Getenv("PATH")
	home := testutil.TempDir(t)
	dir := filepath.Join(home, "stores")
	if err := testutil.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", dir)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "absent"))
	t.Setenv("PATH", t.TempDir())
	for _, kind := range []string{"pass", "libsecret"} {
		path, _ := store.ManifestPath(dir, kind+":team")
		data, _ := store.EncodeManifest([]store.ManifestRecord{{Key: "TOKEN", Account: "0123456789abcdef0123456789abcdef"}}, kind)
		if err := testutil.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	status, out, _ := passCLI(t, []string{"list"}, nil)
	if status != 0 || !strings.Contains(out, "pass:team\n") || !strings.Contains(out, "libsecret:team\n") {
		t.Fatal("same-name discovery differs")
	}
	for _, args := range [][]string{{"show", "pass:team"}, {"show", "--format=json", "pass:team"}, {"list", "--format=json"}, {"completion", "-f", "pass:team"}, {"doctor", "pass:team"}} {
		status, out, _ := passCLI(t, args, nil)
		if status != 0 || strings.Contains(out, "synthetic-private") {
			t.Fatal("metadata required pass executable")
		}
	}
	for _, ref := range []string{"pass:team", "pass:", "pass:../outside"} {
		if !providerRef(ref) {
			t.Fatal("pass prefix not classified before file branch")
		}
		status, _, _ := passCLI(t, []string{"stash", ref, "TOKEN"}, []byte("synthetic-private"))
		if status == 0 {
			t.Fatal("unavailable provider stash succeeded")
		}
	}
	loc := store.Locator{IsFile: func(string) bool { t.Fatal("pass reference probed plaintext path"); return false }}
	if ref, err := loc.Resolve("pass:team"); err != nil || ref != "pass:team" {
		t.Fatal("pass resolution fell back")
	}
	if runtime.GOOS == "windows" {
		return
	}
	// Frozen Bash discovery sees only legacy *.keys, never the optional suffix.
	bash, err := exec.LookPath("/bin/bash")
	if err != nil {
		t.Skip("Bash unavailable")
	}
	cmd := exec.Command(bash, "../../compat/secret", "list")
	cmd.Env = append(os.Environ(), "PATH="+originalPath)
	output, err := cmd.CombinedOutput()
	if err != nil || strings.Contains(string(output), "pass:team") {
		t.Fatal("pass inventory broke legacy Bash discovery")
	}
}
func TestPassRunLoadsAllAndRedacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix synthetic subprocess transport")
	}
	home := t.TempDir()
	dir := filepath.Join(home, "stores")
	passwords := filepath.Join(home, "passwords")
	tools := filepath.Join(home, "tools")
	for _, path := range []string{dir, passwords, tools} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(passwords, ".gpg-id"), []byte("synthetic-recipient"), 0600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
case "$1" in
version) printf '=                  v1.7.4                  =\n';;
show) exec /bin/cat "$PASSWORD_STORE_DIR/$3.gpg";;
*) exit 1;;
esac
`
	if err := os.WriteFile(filepath.Join(tools, "pass"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", dir)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "absent"))
	t.Setenv("PASSWORD_STORE_DIR", passwords)
	t.Setenv("PATH", tools)
	t.Setenv("TOKEN", "inherited-token")
	t.Setenv("UNSELECTED", "inherited-unselected")
	records := []store.ManifestRecord{{Key: "TOKEN", Account: strings.Repeat("1", 32)}, {Key: "UNSELECTED", Labels: map[string]string{"env": "prod"}, Account: strings.Repeat("2", 32)}}
	values := []string{"synthetic-selected", "synthetic-unselected"}
	for i, record := range records {
		path := filepath.Join(passwords, "secret/team", record.Account, "value.gpg")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(values[i]), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := store.EncodeManifest(records, "pass")
	path, _ := store.ManifestPath(dir, "pass:team")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	status, out, diagnostic := passCLI(t, []string{"run", "-f", "pass:team", "--", "/bin/sh", "-c", `test "$TOKEN" = synthetic-selected && test -z "${UNSELECTED+x}" || exit 7; printf '%s' 'synthetic-selected synthetic-unselected'; printf '%s' 'synthetic-selected synthetic-unselected' >&2`}, nil)
	if status != 0 || out != "<redacted> <redacted>" || diagnostic != "<redacted> <redacted>" {
		t.Fatal("run selection/stripping/two-stream redaction differs")
	}
	if err := os.Remove(filepath.Join(passwords, "secret/team", records[1].Account, "value.gpg")); err != nil {
		t.Fatal(err)
	}
	status, out, _ = passCLI(t, []string{"run", "-f", "pass:team", "--key", "TOKEN", "--", "/bin/sh", "-c", "printf child-launched"}, nil)
	if status == 0 || strings.Contains(out, "child-launched") {
		t.Fatal("missing unselected account launched child")
	}
}
