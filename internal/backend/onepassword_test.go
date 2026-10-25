package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func onePasswordRecords() []store.ManifestV2Record {
	return []store.ManifestV2Record{{Key: "API_KEY", Labels: map[string]string{}, ID: strings.Repeat("a", 32), Provider: store.OnePasswordReference{Reference: "op://" + strings.Repeat("v", 26) + "/" + strings.Repeat("i", 26) + "/password", AccountUUID: strings.Repeat("a", 26), Auth: "service-account"}}}
}
func fakeOnePassword(t *testing.T) (string, []string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("transport is Unix only")
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "op")
	log := filepath.Join(dir, "calls.jsonl")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", executable, "../../testdata/onepassword/fake-op.go")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake-op: %v\n%s", err, output)
	}
	// Explicit allowlist: never copy inherited OP variables or a real home/config.
	env := []string{"HOME=" + dir, "PATH=" + dir, "OP_CONFIG_DIR=" + filepath.Join(dir, "config"), "XDG_CACHE_HOME=" + filepath.Join(dir, "cache"), "OP_SERVICE_ACCOUNT_TOKEN=synthetic-token", "FAKE_OP_LOG=" + log}
	return executable, env, log
}
func TestOnePasswordValueContract(t *testing.T) {
	for _, raw := range [][]byte{[]byte("exact"), []byte("internal space"), []byte("é"), []byte("'quoted'"), []byte(`"quoted"`), nil, []byte("trailing\n"), []byte("two\n\n"), []byte("a\rb"), []byte("a\x00b"), []byte(" edge"), []byte("edge ")} {
		name := "reject"
		valid := bytes.Equal(raw, []byte("exact")) || bytes.Equal(raw, []byte("internal space")) || bytes.Equal(raw, []byte("é"))
		if valid {
			name = "exact"
		}
		t.Run(name, func(t *testing.T) {
			before := secure.Clone(raw)
			got, err := onePasswordValue(raw)
			defer secure.Clear(got)
			if (err == nil) != valid {
				t.Fatalf("contract: %v", err)
			}
			if valid && !bytes.Equal(got, raw) {
				t.Fatal("bytes changed")
			}
			if !bytes.Equal(before, raw) {
				t.Fatal("borrowed input changed")
			}
			if err != nil && err != errOnePassword {
				t.Fatal("unsafe error")
			}
		})
	}
}
func TestOnePasswordEnvironment(t *testing.T) {
	for _, extra := range []string{"OP_CONNECT_HOST=x", "OP_CONNECT_TOKEN=x", "OP_SESSION_example=x", "OP_ACCOUNT=x", "OP_SERVICE_ACCOUNT_TOKEN=duplicate"} {
		if _, err := onePasswordEnvironment([]string{"OP_SERVICE_ACCOUNT_TOKEN=synthetic-token", extra}); err == nil {
			t.Fatal("accepted conflicting auth")
		}
	}
	if _, err := onePasswordEnvironment(nil); err == nil {
		t.Fatal("missing token accepted")
	}
	env, err := onePasswordEnvironment([]string{"OP_SERVICE_ACCOUNT_TOKEN=synthetic-token", "OP_DEBUG=true", "OP_CACHE=true", "OP_BIOMETRIC_UNLOCK_ENABLED=true"})
	if err != nil {
		t.Fatal(err)
	}
	if len(env) != 4 {
		t.Fatal("unsafe overrides retained")
	}
}
func TestOnePasswordFakeTransport(t *testing.T) {
	executable, env, log := fakeOnePassword(t)
	for _, scenario := range []string{"success", "wrong-account", "missing-account", "duplicate-account", "unauthenticated", "partial-failure", "rate-limit", "revoked", "denied", "stdout-cap", "stderr-cap", "newline", "pipe-holder", "stall"} {
		t.Run(scenario, func(t *testing.T) {
			budget := 2 * time.Second
			if scenario == "stall" {
				budget = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			p, err := newOnePassword(ctx, "secret/test", onePasswordRecords(), executable, append(env, "FAKE_OP_SCENARIO="+scenario))
			if err != nil {
				t.Fatal(err)
			}
			value, err := p.Get("secret/test", strings.Repeat("a", 32))
			defer secure.Clear(value)
			if scenario == "success" {
				if err != nil || !bytes.Equal(value, []byte("synthetic-value")) {
					t.Fatalf("success: %v", err)
				}
			} else if err != errOnePassword || len(value) != 0 {
				t.Fatalf("unsafe failure: %v", err)
			}
			if p.Put("", "", "", []byte("synthetic")) != ErrReadOnly || p.Delete("", "") != ErrReadOnly {
				t.Fatal("writable provider")
			}
			if _, err := p.Get("secret/other", strings.Repeat("a", 32)); err == nil {
				t.Fatal("service escaped binding")
			}
			if _, err := p.Get("secret/test", strings.Repeat("b", 32)); err == nil {
				t.Fatal("ID escaped binding")
			}
		})
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var event struct {
			Args []string `json:"args"`
			EOF  bool     `json:"eof"`
			TTY  bool     `json:"tty"`
		}
		if json.Unmarshal(line, &event) != nil || !event.EOF || event.TTY {
			t.Fatal("provider had input or controlling terminal")
		}
	}
	if bytes.Contains(data, []byte("synthetic-token")) || bytes.Contains(data, []byte("synthetic-value")) {
		t.Fatal("values in argv log")
	}
}
func TestOnePasswordMissingExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix transport")
	}
	p, err := newOnePassword(context.Background(), "secret/test", onePasswordRecords(), filepath.Join(t.TempDir(), "missing-op"), []string{"OP_SERVICE_ACCOUNT_TOKEN=synthetic-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get("secret/test", strings.Repeat("a", 32)); err != errOnePassword {
		t.Fatalf("missing executable: %v", err)
	}
}
func TestOnePasswordFakeTTY(t *testing.T) {
	if os.Getenv("SECRET_ONEPASSWORD_PTY_PARENT") == "1" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Fatal("test parent has no controlling terminal")
		}
		tty.Close()
	}
	executable, env, log := fakeOnePassword(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := newOnePassword(ctx, "secret/test", onePasswordRecords(), executable, env)
	if err != nil {
		t.Fatal(err)
	}
	value, err := p.Get("secret/test", strings.Repeat("a", 32))
	secure.Clear(value)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	if !bytes.Contains(data, []byte(`"tty":false`)) || bytes.Contains(data, []byte(`"tty":true`)) {
		t.Fatal("controlling terminal inherited")
	}
}
func TestOnePasswordOutputClearing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	buffer := &onePasswordOutput{data: make([]byte, 4), cancel: cancel}
	if _, err := buffer.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := buffer.Write([]byte("5")); err == nil || ctx.Err() == nil {
		t.Fatal("output cap did not cancel")
	}
	secure.Clear(buffer.data)
	if !bytes.Equal(buffer.data, make([]byte, 4)) {
		t.Fatal("buffer not cleared")
	}
}
