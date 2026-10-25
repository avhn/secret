package backend

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/transport"
)

func TestOnePasswordDefaultDispatchAndWrites(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "absent")
	if OnePasswordEnabled() {
		t.Fatal("activation gate open")
	}
	if _, _, _, err := Dispatch("onepassword:test"); err != ErrUnsupported {
		t.Fatal(err)
	}
	if _, _, _, err := DispatchWith("onepassword:test", &onePassword{}); err != ErrUnsupported {
		t.Fatal("injection enabled default dispatch")
	}
	if _, _, _, err := OpenRead(context.Background(), directory, "onepassword:test"); err != ErrUnsupported {
		t.Fatal(err)
	}
	if _, err := ListNames(directory, "onepassword:test"); err != ErrUnsupported {
		t.Fatal(err)
	}
	if err := Stash(directory, "onepassword:test", "TOKEN", nil, []byte("\n"), nil); err != ErrReadOnly {
		t.Fatal("stash normalized before preflight")
	}
	if err := (Transaction{SecretsDir: directory, Reference: "onepassword:test"}).Apply(nil); err != ErrReadOnly {
		t.Fatal("transaction validated before preflight")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("disabled/write operation created directory")
	}
}
func TestOnePasswordBoundSnapshot(t *testing.T) {
	executable, env, log := fakeOnePassword(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "test.onepassword-keys")
	original := onePasswordRecords()
	data, _ := store.EncodeManifestV2(original, "onepassword")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records, provider, service, err := openOnePasswordRead(ctx, directory, "onepassword:test", executable, env)
	if err != nil {
		t.Fatal(err)
	}
	moved := onePasswordRecords()
	moved[0].Provider.Reference = strings.TrimSuffix(moved[0].Provider.Reference, "password") + "other"
	data, _ = store.EncodeManifestV2(moved, "onepassword")
	os.WriteFile(path, data, 0600)
	value, err := provider.Get(service, records[0].Account)
	defer secure.Clear(value)
	if err != nil || !bytes.Equal(value, []byte("synthetic-value")) {
		t.Fatalf("snapshot retargeted: %v", err)
	}
	value2, err := provider.Get(service, records[0].Account)
	secure.Clear(value2)
	if err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(log)
	if bytes.Count(calls, []byte(`"whoami"`)) != 1 || bytes.Count(calls, []byte(`"read"`)) != 2 {
		t.Fatal("identity verification order changed")
	}
	cancel()
	if _, err := provider.Get(service, records[0].Account); err != errOnePassword {
		t.Fatal("expired invocation allowed read")
	}
}

// Exercise real fake-op transport bytes through the unchanged literal filter,
// independently of the CLI injection tests for environment/launch supervision.
func TestOnePasswordFakeAllRecordRedaction(t *testing.T) {
	executable, env, log := fakeOnePassword(t)
	directory := t.TempDir()
	records := onePasswordRecords()
	other := records[0]
	other.ID = strings.Repeat("b", 32)
	other.Labels = map[string]string{"env": "prod"}
	other.Provider.Reference = strings.TrimSuffix(other.Provider.Reference, "password") + "other"
	records = append(records, other)
	data, err := store.EncodeManifestV2(records, "onepassword")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "test.onepassword-keys"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inventory, provider, service, err := openOnePasswordRead(ctx, directory, "onepassword:test", executable, env)
	if err != nil {
		t.Fatal(err)
	}
	var values [][]byte
	defer func() {
		for _, value := range values {
			secure.Clear(value)
		}
	}()
	for _, record := range inventory {
		value, err := provider.Get(service, record.Account)
		if err != nil {
			t.Fatal(err)
		}
		values = append(values, value)
	}
	matcher, err := transport.NewMatcher(values)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		var output bytes.Buffer
		reader := &onePasswordByteReader{data: []byte("synthetic-value synthetic-unselected")}
		if err := matcher.Filter(reader, &output); err != nil {
			t.Fatal(err)
		}
		if output.String() != "<redacted> <redacted>" {
			t.Fatal("registered unselected bytes escaped filter")
		}
	}
	calls, _ := os.ReadFile(log)
	if bytes.Count(calls, []byte(`"read"`)) != 2 {
		t.Fatal("not all registered fields fetched")
	}
}

type onePasswordByteReader struct{ data []byte }

func (reader *onePasswordByteReader) Read(out []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	if len(out) == 0 {
		return 0, nil
	}
	out[0] = reader.data[0]
	reader.data = reader.data[1:]
	return 1, nil
}
