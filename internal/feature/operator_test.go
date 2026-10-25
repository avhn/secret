package feature

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const operatorAccountA = "11111111111111111111111111111111"
const operatorAccountB = "22222222222222222222222222222222"

type operatorProvider struct {
	values                       map[string][]byte
	reads                        [][]byte
	gets, puts, deletes          int
	failGet, failPut, failDelete bool
}

func (provider *operatorProvider) Get(_, account string) ([]byte, error) {
	provider.gets++
	value := secure.Clone(provider.values[account])
	provider.reads = append(provider.reads, value)
	if provider.failGet {
		return value, errors.New("synthetic-provider-stderr-sentinel")
	}
	return value, nil
}
func (provider *operatorProvider) Put(_, account, _ string, value []byte) error {
	provider.puts++
	if provider.failPut {
		return errors.New("synthetic-provider-stderr-sentinel")
	}
	if provider.values == nil {
		provider.values = make(map[string][]byte)
	}
	provider.values[account] = secure.Clone(value)
	return nil
}
func (provider *operatorProvider) Delete(_, account string) error {
	provider.deletes++
	if provider.failDelete {
		return errors.New("synthetic-provider-stderr-sentinel")
	}
	secure.Clear(provider.values[account])
	delete(provider.values, account)
	return nil
}
func newTestOperator(t *testing.T) Operator {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("operator persistence awaits Windows permission gate")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return Operator{SecretsDir: directory, Providers: make(map[string]backend.Provider), Confirm: func(OperatorResult) error { return nil }}
}
func writeOperatorManifest(t *testing.T, directory, reference string, records []store.ManifestRecord) {
	t.Helper()
	kind, name, _ := strings.Cut(reference, ":")
	data, err := store.EncodeManifest(records, kind)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".keys"), data, 0600); err != nil {
		t.Fatal(err)
	}
}
func assertOperatorZeroed(t *testing.T, values ...[]byte) {
	t.Helper()
	for _, value := range values {
		for _, b := range value[:cap(value)] {
			if b != 0 {
				t.Fatal("owned byte buffer was not cleared")
			}
		}
	}
}
func assertNoOperatorLeak(t *testing.T, result OperatorResult, err error) {
	t.Helper()
	data, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, sentinel := range [][]byte{[]byte("synthetic-value-sentinel"), []byte("synthetic-provider-stderr-sentinel")} {
		if bytes.Contains(data, sentinel) || err != nil && bytes.Contains([]byte(err.Error()), sentinel) {
			t.Fatal("operator metadata or error leaked a sentinel")
		}
	}
}

func TestOperatorExportPreflightNoValueCalls(t *testing.T) {
	for _, name := range []string{"bare source", "relative source", "file destination", "same target", "shared manifest", "missing policy", "bad policy", "bad key", "duplicate keys", "missing key", "bad selectors", "ambiguous", "collision", "recovery"} {
		t.Run(name, func(t *testing.T) {
			operator := newTestOperator(t)
			source, target := &operatorProvider{}, &operatorProvider{}
			operator.Providers["libsecret:source"], operator.Providers["libsecret:target"] = source, target
			records := []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}}
			writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", records)
			request := ExportRequest{Source: "libsecret:source", Target: "libsecret:target", OnConflict: "fail"}
			switch name {
			case "bare source":
				request.Source = "source"
			case "relative source":
				request.Source = "file:relative"
			case "file destination":
				request.Target = "file:" + filepath.Join(t.TempDir(), "out")
			case "same target":
				request.Target = request.Source
			case "shared manifest":
				request.Target = "keychain:source"
			case "missing policy":
				request.OnConflict = ""
			case "bad policy":
				request.OnConflict = "replace"
			case "bad key":
				request.Keys = []string{"--reveal"}
			case "duplicate keys":
				request.Keys = []string{"TOKEN", "TOKEN"}
			case "missing key":
				request.Keys = []string{"MISSING"}
			case "bad selectors":
				request.Selectors = store.Selectors{"env": "invalid value"}
			case "ambiguous":
				request.Selectors = store.Selectors{"env": "prod", "region": "eu"}
				writeOperatorManifest(t, operator.SecretsDir, request.Source, []store.ManifestRecord{{Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: operatorAccountA}, {Key: "TOKEN", Labels: map[string]string{"region": "eu"}, Account: operatorAccountB}})
			case "collision":
				writeOperatorManifest(t, operator.SecretsDir, request.Target, records)
			case "recovery":
				if err := os.WriteFile(filepath.Join(operator.SecretsDir, "target.keys.recovery"), []byte("not a recovery record"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			result, err := operator.Export(context.Background(), request)
			if err == nil {
				t.Fatal("invalid preflight accepted")
			}
			if source.gets+source.puts+source.deletes+target.gets+target.puts+target.deletes != 0 {
				t.Fatal("provider called during invalid preflight")
			}
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestOperatorExportSelectionAndCleanup(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(map[bool]string{false: "unlabeled", true: "explicit labels"}[selected], func(t *testing.T) {
			operator := newTestOperator(t)
			source := &operatorProvider{values: map[string][]byte{operatorAccountA: []byte("synthetic-value-sentinel"), operatorAccountB: []byte("synthetic-labeled-sentinel")}}
			target := &operatorProvider{}
			operator.Providers["libsecret:source"], operator.Providers["libsecret:target"] = source, target
			writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}, {Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: operatorAccountB}})
			request := ExportRequest{Source: "libsecret:source", Target: "libsecret:target", OnConflict: "fail"}
			if selected {
				request.Selectors = store.Selectors{"env": "prod"}
			}
			confirmations := 0
			operator.Confirm = func(result OperatorResult) error {
				confirmations++
				if source.gets != 0 || target.puts != 0 || len(result.Records) != 1 {
					t.Fatal("consent is not before value access")
				}
				if (len(result.Records[0].Labels) != 0) != selected {
					t.Fatal("wrong exact identity confirmed")
				}
				return nil
			}
			result, err := operator.Export(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if confirmations != 1 || source.gets != 1 || target.puts != 1 || target.gets != 1 {
				t.Fatal("unexpected provider or consent calls")
			}
			assertOperatorZeroed(t, source.reads...)
			assertOperatorZeroed(t, target.reads...)
			assertNoOperatorLeak(t, result, err)
			manifest, err := store.ReadManifest(filepath.Join(operator.SecretsDir, "target.keys"), "libsecret")
			if err != nil || len(manifest) != 1 || len(manifest[0].Labels) != len(request.Selectors) {
				t.Fatal("export did not publish the selected identity")
			}
		})
	}
}

func TestOperatorExportDryRunConsentFailureAndLockedRecheck(t *testing.T) {
	for _, mode := range []string{"dry", "declined", "nil consent", "locked conflict", "source failure", "target failure", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			operator := newTestOperator(t)
			source := &operatorProvider{values: map[string][]byte{operatorAccountA: []byte("synthetic-value-sentinel")}}
			target := &operatorProvider{}
			operator.Providers["libsecret:source"], operator.Providers["libsecret:target"] = source, target
			writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
			request := ExportRequest{Source: "libsecret:source", Target: "libsecret:target", OnConflict: "fail"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := secure.ErrConsent
			switch mode {
			case "dry":
				request.DryRun = true
				operator.Confirm = func(OperatorResult) error { t.Fatal("dry run requested consent"); return nil }
				want = nil
			case "declined":
				operator.Confirm = func(OperatorResult) error { return errors.New("synthetic-provider-stderr-sentinel") }
			case "nil consent":
				operator.Confirm = nil
			case "locked conflict":
				operator.Confirm = func(OperatorResult) error {
					writeOperatorManifest(t, operator.SecretsDir, request.Target, []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountB}})
					return nil
				}
				want = secure.ErrConflict
			case "source failure":
				source.failGet = true
				want = secure.ErrTransaction
			case "target failure":
				target.failPut = true
				want = secure.ErrRecovery
			case "canceled":
				cancel()
				want = secure.ErrTransaction
			}
			result, err := operator.Export(ctx, request)
			if err != want {
				t.Fatalf("got %v, want %v", err, want)
			}
			if mode == "dry" || mode == "declined" || mode == "nil consent" || mode == "canceled" {
				if source.gets+target.puts != 0 {
					t.Fatal("value fetched without consent or during dry run/cancellation")
				}
			}
			if mode == "locked conflict" && target.puts != 0 {
				t.Fatal("locked recheck overwrote collision")
			}
			if mode == "target failure" {
				if _, err := store.ReadRecovery(filepath.Join(operator.SecretsDir, "target.keys"), "libsecret"); err != nil {
					t.Fatal("recovery intent missing")
				}
			}
			assertOperatorZeroed(t, source.reads...)
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestOperatorLifecycleExactFileIdentities(t *testing.T) {
	operator := newTestOperator(t)
	path := filepath.Join(t.TempDir(), "synthetic.env")
	initial := []byte("TOKEN=base\r\n[env=prod]\r\n export TOKEN='synthetic-value-sentinel'\r\nPEER=keep\r\n")
	if err := os.WriteFile(path, initial, 0600); err != nil {
		t.Fatal(err)
	}
	request := LifecycleRequest{Action: store.ActionRename, Reference: "file:" + path, Key: "TOKEN", NewKey: "RENAMED", Labels: map[string]string{"env": "prod"}}
	operator.Confirm = func(result OperatorResult) error {
		if result.Records[0].NewKey != "RENAMED" {
			t.Fatal("rename destination missing from consent")
		}
		return nil
	}
	if _, err := operator.Lifecycle(request, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	defer secure.Clear(data)
	if !bytes.Equal(data, []byte("TOKEN=base\r\n[env=prod]\r\n export RENAMED='synthetic-value-sentinel'\r\nPEER=keep\r\n")) {
		t.Fatal("rename changed peer bytes or identity")
	}
	operator.Confirm = func(OperatorResult) error { return nil }
	request.Action, request.Key, request.NewKey = store.ActionRotate, "RENAMED", ""
	input := []byte("synthetic-new-sentinel")
	if _, err := operator.Lifecycle(request, func() ([]byte, error) { return input, nil }); err != nil {
		t.Fatal(err)
	}
	assertOperatorZeroed(t, input)
	request.Action = store.ActionDelete
	if _, err := operator.Lifecycle(request, nil); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	defer secure.Clear(data)
	if bytes.Contains(data, []byte("RENAMED=")) || !bytes.Contains(data, []byte("TOKEN=base\r\n")) || !bytes.Contains(data, []byte("PEER=keep\r\n")) {
		t.Fatal("delete did not preserve peers")
	}
}

func TestOperatorLifecyclePreflightAndInputFailure(t *testing.T) {
	operator := newTestOperator(t)
	provider := &operatorProvider{}
	operator.Providers["libsecret:source"] = provider
	writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}, {Key: "PEER", Account: operatorAccountB}})
	for _, request := range []LifecycleRequest{
		{Action: store.ActionRotate, Reference: "source", Key: "TOKEN"},
		{Action: store.ActionRotate, Reference: "libsecret:source", Key: "TOKEN", Labels: map[string]string{"env": "prod"}},
		{Action: store.ActionRename, Reference: "libsecret:source", Key: "TOKEN", NewKey: "PEER"},
		{Action: store.ActionRename, Reference: "libsecret:source", Key: "TOKEN", NewKey: "bad-key"},
		{Action: store.ActionDelete, Reference: "libsecret:source", Key: "TOKEN", NewKey: "PEER"},
	} {
		if _, err := operator.Lifecycle(request, func() ([]byte, error) { t.Fatal("hidden input read during invalid preflight"); return nil, nil }); err == nil {
			t.Fatal("invalid lifecycle accepted")
		}
	}
	input := []byte("synthetic-value-sentinel")
	result, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: "libsecret:source", Key: "TOKEN"}, func() ([]byte, error) { return input, errors.New("synthetic-provider-stderr-sentinel") })
	if err != secure.ErrInput || provider.gets+provider.puts+provider.deletes != 0 {
		t.Fatal("input failure reached provider")
	}
	assertOperatorZeroed(t, input)
	assertNoOperatorLeak(t, result, err)
}

func TestOperatorLifecycleProviderTransactions(t *testing.T) {
	for _, action := range []store.OperatorAction{store.ActionRename, store.ActionRotate, store.ActionDelete} {
		t.Run(string(action), func(t *testing.T) {
			operator := newTestOperator(t)
			provider := &operatorProvider{values: map[string][]byte{operatorAccountA: []byte("synthetic-value-sentinel"), operatorAccountB: []byte("synthetic-peer")}}
			operator.Providers["libsecret:source"] = provider
			writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}, {Key: "PEER", Account: operatorAccountB}})
			request := LifecycleRequest{Action: action, Reference: "libsecret:source", Key: "TOKEN"}
			var readValue func() ([]byte, error)
			var input []byte
			if action == store.ActionRename {
				request.NewKey = "RENAMED"
			}
			if action == store.ActionRotate {
				input = []byte("synthetic-rotated")
				readValue = func() ([]byte, error) { return input, nil }
			}
			result, err := operator.Lifecycle(request, readValue)
			if err != nil {
				t.Fatal(err)
			}
			manifest, err := store.ReadManifest(filepath.Join(operator.SecretsDir, "source.keys"), "libsecret")
			if err != nil {
				t.Fatal(err)
			}
			if provider.deletes != 1 || provider.values[operatorAccountA] != nil || !bytes.Equal(provider.values[operatorAccountB], []byte("synthetic-peer")) {
				t.Fatal("old account cleanup changed a peer or left the replaced account")
			}
			if action == store.ActionDelete {
				if len(manifest) != 1 || provider.gets+provider.puts != 0 {
					t.Fatal("delete fetched a value or retained its identity")
				}
			} else {
				if len(manifest) != 2 || manifest[0].Account == operatorAccountA || manifest[1].Account != operatorAccountB || provider.puts != 1 {
					t.Fatal("fresh-account publication did not preserve peers")
				}
				want := []byte("synthetic-value-sentinel")
				if action == store.ActionRename && manifest[0].Key != "RENAMED" {
					t.Fatal("renamed key missing")
				}
				if action == store.ActionRotate {
					want = []byte("synthetic-rotated")
				}
				if !bytes.Equal(provider.values[manifest[0].Account], want) {
					t.Fatal("published account has incorrect synthetic bytes")
				}
			}
			assertOperatorZeroed(t, input)
			assertOperatorZeroed(t, provider.reads...)
			assertNoOperatorLeak(t, result, err)
		})
	}
}

func TestOperatorExportFileSelectionDrift(t *testing.T) {
	operator := newTestOperator(t)
	path := filepath.Join(t.TempDir(), "synthetic.env")
	if err := os.WriteFile(path, []byte("TOKEN=synthetic-original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := &operatorProvider{}
	operator.Providers["libsecret:target"] = provider
	operator.Confirm = func(result OperatorResult) error {
		if len(result.Records) != 1 || result.Records[0].Key != "TOKEN" {
			t.Fatal("wrong planned key")
		}
		return os.WriteFile(path, []byte("TOKEN=synthetic-original\n[env=prod]\nTOKEN=synthetic-reselected\n"), 0600)
	}
	result, err := operator.Export(context.Background(), ExportRequest{Source: "file:" + path, Target: "libsecret:target", Selectors: store.Selectors{"env": "prod"}, OnConflict: "fail"})
	if err != secure.ErrConflict || provider.gets+provider.puts != 0 {
		t.Fatal("selection changed after consent but export fetched destination values")
	}
	assertNoOperatorLeak(t, result, err)
}

func TestOperatorLifecyclePendingRecoveryBeforeHiddenInput(t *testing.T) {
	operator := newTestOperator(t)
	provider := &operatorProvider{}
	operator.Providers["libsecret:source"] = provider
	writeOperatorManifest(t, operator.SecretsDir, "libsecret:source", []store.ManifestRecord{{Key: "TOKEN", Account: operatorAccountA}})
	if err := os.WriteFile(filepath.Join(operator.SecretsDir, "source.keys.recovery"), []byte("synthetic invalid intent"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := operator.Lifecycle(LifecycleRequest{Action: store.ActionRotate, Reference: "libsecret:source", Key: "TOKEN"}, func() ([]byte, error) { t.Fatal("pending recovery requested hidden input"); return nil, nil })
	if err != secure.ErrRecovery || provider.gets+provider.puts+provider.deletes != 0 {
		t.Fatal("pending recovery reached provider")
	}
}

func TestOperatorWindowsInvalidRequestsBeforeAccess(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows invalid request ordering")
	}
	operator := Operator{Confirm: func(OperatorResult) error { t.Fatal("invalid request requested consent"); return nil }}
	if _, err := operator.Export(context.Background(), ExportRequest{}); err != secure.ErrInvalidRequest {
		t.Fatal(err)
	}
	if _, err := operator.Import(context.Background(), ImportRequest{}); err != secure.ErrInvalidRequest {
		t.Fatal(err)
	}
	if _, err := operator.Lifecycle(LifecycleRequest{}, nil); err != secure.ErrInvalidRequest {
		t.Fatal(err)
	}
}
