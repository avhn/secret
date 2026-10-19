//go:build linux || darwin

package backend_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// sampleOperatorArgv records only argv at the actual provider executable boundary.
// It never copies stdin or provider output. Production transports still run the
// real CLI against the isolated session or explicit disposable keychain.
func sampleOperatorArgv(t *testing.T, root, tool string) string {
	t.Helper()
	actual, err := exec.LookPath(tool)
	if err != nil {
		t.Fatal("required provider executable missing")
	}
	tools := filepath.Join(root, "tools")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(root, "argv")
	script := []byte("#!/bin/sh\numask 077\nprintf '%s\\n' \"$@\" >>\"$SECRET_OPERATOR_ARGV\"\nexec \"$SECRET_OPERATOR_TOOL\" \"$@\"\n")
	if err := os.WriteFile(filepath.Join(tools, tool), script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECRET_OPERATOR_ARGV", log)
	t.Setenv("SECRET_OPERATOR_TOOL", actual)
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	return log
}

func runProviderOperators(t *testing.T, root, kind string) {
	t.Helper()
	tool := "secret-tool"
	if kind == "keychain" {
		tool = "security"
	}
	argvLog := sampleOperatorArgv(t, root, tool)
	dir := filepath.Join(root, "stores")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "synthetic.env")
	initial := []byte("synthetic-m3-initial-é-$TOKEN")
	rotated := []byte("synthetic-m3-rotated-é-$TOKEN")
	defer secure.Clear(initial)
	defer secure.Clear(rotated)
	if err := os.WriteFile(source, append(append([]byte("TOKEN="), initial...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	ref := kind + ":m3-operator"
	provider, _, service, err := backend.Dispatch(ref)
	if err != nil {
		t.Fatal(err)
	}
	// Remember only exact accounts created by this test. On assertion failure,
	// remove registered accounts, never enumerate or delete unrelated entries.
	accounts := make(map[string]bool)
	t.Cleanup(func() {
		for account := range accounts {
			_ = provider.Delete(service, account)
		}
	})
	manifest := func(key string) store.ManifestRecord {
		t.Helper()
		records, err := store.ReadManifest(filepath.Join(dir, "m3-operator.keys"), kind)
		if err != nil {
			t.Fatal("operator manifest unavailable")
		}
		for _, record := range records {
			accounts[record.Account] = true
			if record.Key == key {
				return record
			}
		}
		t.Fatal("operator identity missing")
		return store.ManifestRecord{}
	}
	checkValue := func(record store.ManifestRecord, want []byte) {
		t.Helper()
		got, err := provider.Get(service, record.Account)
		defer secure.Clear(got)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("operator value readback mismatch")
		}
	}
	checkGone := func(record store.ManifestRecord) {
		t.Helper()
		got, err := provider.Get(service, record.Account)
		defer secure.Clear(got)
		if err == nil {
			t.Fatal("obsolete exact account still resolves")
		}
	}
	confirmations := 0
	operator := feature.Operator{SecretsDir: dir, Confirm: func(result feature.OperatorResult) error {
		// The real controlling-terminal boundary is exercised by the PTY suite.
		// Here consent bridges only synthetic names to the actual provider path.
		if result.Target != ref || len(result.Records) != 1 || result.Records[0].Key == "" {
			t.Fatal("incorrect names-only consent request")
		}
		confirmations++
		return nil
	}}
	ctx := context.Background()
	request := feature.ExportRequest{Source: "file:" + source, Target: ref, OnConflict: "fail"}
	if _, err := operator.Export(ctx, request); err != nil {
		t.Fatal("real-provider export failed", err)
	}
	first := manifest("TOKEN")
	checkValue(first, initial)
	before, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Export(ctx, request); !errors.Is(err, secure.ErrConflict) {
		t.Fatal("destination collision not rejected")
	}
	after, err := os.ReadFile(argvLog)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("collision preflight contacted value provider")
	}
	labels := map[string]string{"env": "prod"}
	if _, err := operator.Import(ctx, feature.ImportRequest{Source: "dotenv:" + source, Target: ref, Labels: labels, Mappings: []feature.FieldMapping{{Field: "TOKEN", Key: "IMPORTED"}}}); err != nil {
		t.Fatal("real-provider import failed", err)
	}
	imported := manifest("IMPORTED")
	checkValue(imported, initial)
	if _, err := operator.Lifecycle(feature.LifecycleRequest{Action: store.ActionRotate, Reference: ref, Key: "TOKEN"}, func() ([]byte, error) {
		return secure.Clone(rotated), nil
	}); err != nil {
		t.Fatal("real-provider rotation failed", err)
	}
	second := manifest("TOKEN")
	if second.Account == first.Account {
		t.Fatal("rotation reused the previous account")
	}
	checkValue(second, rotated)
	checkGone(first)
	if _, err := operator.Lifecycle(feature.LifecycleRequest{Action: store.ActionRename, Reference: ref, Key: "TOKEN", NewKey: "RENAMED"}, nil); err != nil {
		t.Fatal("real-provider rename failed", err)
	}
	third := manifest("RENAMED")
	if third.Account == second.Account {
		t.Fatal("rename reused the previous account")
	}
	checkValue(third, rotated)
	checkGone(second)
	for _, request := range []feature.LifecycleRequest{
		{Action: store.ActionDelete, Reference: ref, Key: "RENAMED"},
		{Action: store.ActionDelete, Reference: ref, Key: "IMPORTED", Labels: labels},
	} {
		if _, err := operator.Lifecycle(request, nil); err != nil {
			t.Fatal("real-provider delete failed", err)
		}
	}
	checkGone(third)
	checkGone(imported)
	if confirmations != 6 {
		t.Fatal("missing per-operation consent")
	}
	metadata, err := feature.ReadMetadata(ref, dir)
	if err != nil || len(metadata.Records) != 0 {
		t.Fatal("deleted identities remain in manifest")
	}
	if _, err := store.ReadRecovery(filepath.Join(dir, "m3-operator.keys"), kind); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("successful operator left recovery intent")
	}
	args, err := os.ReadFile(argvLog)
	if err != nil || len(args) == 0 || bytes.Contains(args, initial) || bytes.Contains(args, rotated) {
		t.Fatal("provider argv sampling failed or exposed value")
	}
	for _, value := range [][]byte{initial, rotated} {
		encoded := hex.AppendEncode(nil, value)
		exposed := bytes.Contains(args, encoded)
		secure.Clear(encoded)
		if exposed {
			t.Fatal("provider argv exposed encoded value")
		}
	}
	for _, operation := range map[string][]string{"libsecret": {"store", "lookup", "clear"}, "keychain": {"-i", "find-generic-password", "delete-generic-password"}}[kind] {
		if !strings.Contains(string(args), operation+"\n") {
			t.Fatal("provider argv sample missing an operation")
		}
	}
}
