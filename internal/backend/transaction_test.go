package backend

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func transactionPlatform(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("operator persistence requires Unix private permissions until M5a")
	}
}

// transactionSpy wraps the existing disposable directory stub. Borrowed input
// and returned readback buffers remain observable solely to assert cleanup.
type transactionSpy struct {
	*stub
	calls    []string
	inputs   [][]byte
	outputs  [][]byte
	fail     string
	mismatch bool
	observe  func(op, account string)
}

func (spy *transactionSpy) call(op, account string) error {
	spy.calls = append(spy.calls, op+" "+account)
	if spy.observe != nil {
		spy.observe(op, account)
	}
	if spy.fail == op {
		return errors.New("synthetic-provider-stderr-sentinel")
	}
	return nil
}

func (spy *transactionSpy) Put(service, account, label string, value []byte) error {
	spy.inputs = append(spy.inputs, value)
	if err := spy.call("put", account); err != nil {
		return err
	}
	return spy.stub.Put(service, account, label, value)
}

func (spy *transactionSpy) Get(service, account string) ([]byte, error) {
	value, err := spy.stub.Get(service, account)
	if spy.mismatch && len(value) > 0 {
		value[0] ^= 1
	}
	spy.outputs = append(spy.outputs, value)
	if failure := spy.call("get", account); failure != nil {
		return value, failure
	}
	return value, err
}

func (spy *transactionSpy) Delete(service, account string) error {
	if err := spy.call("delete", account); err != nil {
		return err
	}
	return spy.stub.Delete(service, account)
}

func transactionFixture(t *testing.T) (string, *stub, []store.ManifestRecord) {
	t.Helper()
	dir := t.TempDir()
	provider := &stub{dir: filepath.Join(dir, "provider"), backend: "libsecret"}
	records := []store.ManifestRecord{
		{Key: "KEY", Account: "11111111111111111111111111111111"},
		{Key: "OTHER", Labels: map[string]string{"env": "dev"}, Account: "22222222222222222222222222222222"},
	}
	for _, record := range records {
		if err := provider.Put("secret/demo", record.Account, "", []byte("synthetic-prior-"+record.Key)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.WithWriteLock(dir, func() error {
		return store.PublishManifestLocked(filepath.Join(dir, "demo.keys"), "libsecret", records)
	}); err != nil {
		t.Fatal(err)
	}
	return dir, provider, records
}

func TestTransactionOrderingAndByteCleanup(t *testing.T) {
	transactionPlatform(t)
	dir, provider, prior := transactionFixture(t)
	path := filepath.Join(dir, "demo.keys")
	spy := &transactionSpy{stub: provider}
	spy.observe = func(op, account string) {
		intent, err := store.ReadRecovery(path, "libsecret")
		if err != nil || len(intent.Prepared) != 2 || len(intent.Obsolete) != 2 {
			t.Fatal("provider call occurred before complete durable recovery intent")
		}
		records, err := store.ReadManifest(path, "libsecret")
		if err != nil {
			t.Fatal(err)
		}
		if op == "delete" {
			for _, record := range records {
				if record.Account == account {
					t.Fatal("deleted a still-published account")
				}
			}
		} else if records[0].Account != prior[0].Account || records[1].Account != prior[1].Account {
			t.Fatal("provider preparation changed the previous manifest")
		}
	}
	value := []byte("synthetic-rotated")
	mutations := []store.Mutation{
		{Kind: store.MutationPut, Key: "KEY", Value: value},
		{Kind: store.MutationRename, Key: "OTHER", NewKey: "RENAMED", Labels: prior[1].Labels},
	}
	if err := (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}).Apply(mutations); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, []byte("synthetic-rotated")) {
		t.Fatal("transaction cleared its caller's borrowed value")
	}
	for _, owned := range append(spy.inputs, spy.outputs...) {
		if !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("owned provider transport buffer was not cleared")
		}
	}
	records, err := store.ReadManifest(path, "libsecret")
	if err != nil || len(records) != 2 || records[0].Key != "KEY" || records[1].Key != "RENAMED" {
		t.Fatal("published batch differs")
	}
	for i, record := range records {
		if record.Account == prior[i].Account {
			t.Fatal("operator reused an old provider account")
		}
		if _, err := os.Stat(provider.path("secret/demo", prior[i].Account)); !os.IsNotExist(err) {
			t.Fatal("old account was not garbage-collected")
		}
		got, err := provider.Get("secret/demo", record.Account)
		want := value
		if i == 1 {
			want = []byte("synthetic-prior-OTHER")
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("fresh account has incorrect bytes")
		}
		secure.Clear(got)
	}
	if _, err := store.ReadRecovery(path, "libsecret"); !os.IsNotExist(err) {
		t.Fatal("successful transaction left recovery intent")
	}
	last := spy.calls[len(spy.calls)-2:]
	if !strings.HasPrefix(last[0], "delete ") || !strings.HasPrefix(last[1], "delete ") {
		t.Fatal("cleanup did not follow all preparation and verification")
	}
}

func TestTransactionPhaseFailures(t *testing.T) {
	transactionPlatform(t)
	for _, tc := range []struct {
		phase     string
		index     int
		published bool
	}{
		{"intent", 0, false},
		{"prepare", 0, false}, {"prepare", 1, false},
		{"verify", 0, false}, {"verify", 1, false},
		{"publish", 0, false}, {"published", 0, true},
		{"cleanup", 0, true}, {"cleanup", 1, true}, {"complete", 0, true},
	} {
		t.Run(fmt.Sprintf("%s-%d", tc.phase, tc.index), func(t *testing.T) {
			dir, provider, prior := transactionFixture(t)
			path := filepath.Join(dir, "demo.keys")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			spy := &transactionSpy{stub: provider}
			transaction := Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}
			mutations := []store.Mutation{
				{Kind: store.MutationPut, Key: "KEY", Value: []byte("synthetic-replacement-one")},
				{Kind: store.MutationPut, Key: "OTHER", Labels: prior[1].Labels, Value: []byte("synthetic-replacement-two")},
			}
			err = transaction.apply(mutations, transactionSteps{account: store.NewAccount, checkpoint: func(phase string, index int) error {
				if phase == tc.phase && index == tc.index {
					return errors.New("synthetic-checkpoint-sentinel")
				}
				return nil
			}})
			want := secure.ErrRecovery
			if tc.phase == "intent" {
				want = secure.ErrTransaction
			}
			if err != want {
				t.Fatalf("phase error = %v, want %v", err, want)
			}
			got, err := os.ReadFile(path)
			if err != nil || (bytes.Equal(got, original) == tc.published) {
				t.Fatal("publication boundary violated")
			}
			if !tc.published {
				for _, record := range prior {
					value, err := provider.Get("secret/demo", record.Account)
					if err != nil || !bytes.Equal(value, []byte("synthetic-prior-"+record.Key)) {
						t.Fatal("pre-publication failure overwrote an old account")
					}
					secure.Clear(value)
				}
			}
			if tc.phase != "intent" {
				intent, err := store.ReadRecovery(path, "libsecret")
				if err != nil || len(intent.Prepared) != 2 || len(intent.Obsolete) != 2 {
					t.Fatal("failure lost exact recovery candidates")
				}
				body, err := os.ReadFile(path + ".recovery")
				if err != nil || bytes.Contains(body, []byte("synthetic-replacement")) || bytes.Contains(body, []byte("synthetic-prior")) {
					t.Fatal("recovery intent contains values")
				}
				calls := len(spy.calls)
				if err := transaction.Apply(mutations); err != secure.ErrRecovery || len(spy.calls) != calls {
					t.Fatal("pending recovery did not stop the next transaction before provider access")
				}
			} else if _, err := os.Stat(path + ".recovery"); !os.IsNotExist(err) {
				t.Fatal("pre-intent failure left recovery")
			}
		})
	}
}

func TestTransactionProviderFailures(t *testing.T) {
	transactionPlatform(t)
	for _, tc := range []struct {
		name, fail          string
		mismatch, published bool
	}{
		{"put", "put", false, false}, {"get", "get", false, false},
		{"verification mismatch", "", true, false}, {"delete", "delete", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, provider, _ := transactionFixture(t)
			path := filepath.Join(dir, "demo.keys")
			original, _ := os.ReadFile(path)
			spy := &transactionSpy{stub: provider, fail: tc.fail, mismatch: tc.mismatch}
			err := (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("synthetic-new")}})
			if err != secure.ErrRecovery || strings.Contains(err.Error(), "sentinel") {
				t.Fatalf("provider failure was not sanitized: %v", err)
			}
			got, _ := os.ReadFile(path)
			if bytes.Equal(got, original) == tc.published {
				t.Fatal("provider failure crossed publication boundary")
			}
			for _, owned := range append(spy.inputs, spy.outputs...) {
				if !bytes.Equal(owned, make([]byte, len(owned))) {
					t.Fatal("provider failure retained an owned buffer")
				}
			}
		})
	}
}

func TestTransactionPreflightAndAccountCollisions(t *testing.T) {
	transactionPlatform(t)
	for _, tc := range []struct {
		name      string
		mutations []store.Mutation
		insert    bool
		generate  func() (string, error)
		want      error
	}{
		{"missing", []store.Mutation{{Kind: store.MutationDelete, Key: "MISSING"}}, false, nil, secure.ErrNotFound},
		{"collision", []store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}, true, nil, secure.ErrConflict},
		{"batch collision", []store.Mutation{{Kind: store.MutationPut, Key: "NEW", Value: []byte("new")}, {Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}, true, nil, secure.ErrConflict},
		{"invalid value", []store.Mutation{{Kind: store.MutationPut, Key: "NEW", Value: []byte("bad\nvalue")}}, false, nil, secure.ErrInvalidRequest},
		{"account collision", []store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}, false, func() (string, error) { return "11111111111111111111111111111111", nil }, secure.ErrConflict},
		{"random failure", []store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}, false, func() (string, error) { return "", errors.New("synthetic-random-sentinel") }, secure.ErrTransaction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, provider, _ := transactionFixture(t)
			spy := &transactionSpy{stub: provider}
			transaction := Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy, FailOnConflict: tc.insert}
			err := transaction.apply(tc.mutations, transactionSteps{account: tc.generate})
			if err != tc.want || len(spy.calls) != 0 {
				t.Fatalf("preflight result: %v, provider calls: %d", err, len(spy.calls))
			}
			if _, err := store.ReadRecovery(filepath.Join(dir, "demo.keys"), "libsecret"); !os.IsNotExist(err) {
				t.Fatal("failed preflight persisted recovery intent")
			}
		})
	}
	// Random collisions retry without touching an existing account.
	dir, provider, prior := transactionFixture(t)
	attempt := 0
	steps := transactionSteps{account: func() (string, error) {
		attempt++
		if attempt == 1 {
			return prior[0].Account, nil
		}
		return "33333333333333333333333333333333", nil
	}}
	if err := (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: provider}).apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}, steps); err != nil || attempt != 2 {
		t.Fatalf("random collision retry: %v, attempts: %d", err, attempt)
	}
}

func TestTransactionDeleteOnlyAndScopedIdentity(t *testing.T) {
	transactionPlatform(t)
	dir, provider, prior := transactionFixture(t)
	spy := &transactionSpy{stub: provider}
	transaction := Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}
	if err := transaction.Apply([]store.Mutation{{Kind: store.MutationDelete, Key: "OTHER", Labels: prior[1].Labels}}); err != nil {
		t.Fatal(err)
	}
	if len(spy.calls) != 1 || !strings.HasPrefix(spy.calls[0], "delete ") {
		t.Fatal("delete-only transaction fetched or prepared values")
	}
	records, err := store.ReadManifest(filepath.Join(dir, "demo.keys"), "libsecret")
	if err != nil || len(records) != 1 || records[0].Account != prior[0].Account {
		t.Fatal("delete changed a peer identity")
	}
	if err := transaction.Apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Labels: map[string]string{"env": "prod"}, Value: []byte("new")}}); err != nil {
		t.Fatal(err)
	}
	records, err = store.ReadManifest(filepath.Join(dir, "demo.keys"), "libsecret")
	if err != nil || len(records) != 2 || records[0].Account != prior[0].Account {
		t.Fatal("scoped put changed a peer identity")
	}
}

func TestTransactionInvalidTargetsAndWindowsRefusal(t *testing.T) {
	dir := t.TempDir()
	spy := &transactionSpy{stub: &stub{dir: filepath.Join(dir, "provider"), backend: "libsecret"}}
	mutations := []store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}
	if runtime.GOOS == "windows" {
		target := filepath.Join(dir, "missing")
		if err := (Transaction{SecretsDir: target, Reference: "libsecret:demo", Provider: spy}).Apply(mutations); err != secure.ErrUnsupported || len(spy.calls) != 0 {
			t.Fatal("Windows did not refuse before provider access")
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatal("Windows created storage")
		}
		return
	}
	for _, reference := range []string{"keychain:../invalid", "libsecret:", "file:/synthetic", "bare"} {
		if err := (Transaction{SecretsDir: dir, Reference: reference, Provider: spy}).Apply(mutations); err != secure.ErrInvalidRequest || len(spy.calls) != 0 {
			t.Fatalf("invalid reference result: %v", err)
		}
	}
	if err := (Transaction{SecretsDir: "relative", Reference: "libsecret:demo", Provider: spy}).Apply(mutations); err != secure.ErrInvalidRequest {
		t.Fatal("relative directory accepted")
	}
	path := filepath.Join(dir, "demo.keys")
	if err := os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if err := (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}).Apply(mutations); err != secure.ErrTransaction || len(spy.calls) != 0 {
		t.Fatal("aliased manifest allowed provider access")
	}
}

func TestTransactionConcurrentWriters(t *testing.T) {
	transactionPlatform(t)
	dir := t.TempDir()
	provider := &stub{dir: filepath.Join(dir, "provider"), backend: "libsecret"}
	const count = 4
	results := make(chan error, count)
	var writers sync.WaitGroup
	for i := range count {
		writers.Go(func() {
			results <- (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: provider, FailOnConflict: true}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: fmt.Sprintf("KEY_%d", i), Value: []byte("synthetic")}})
		})
	}
	writers.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	records, err := store.ReadManifest(filepath.Join(dir, "demo.keys"), "libsecret")
	if err != nil || len(records) != count {
		t.Fatal("concurrent writers lost manifest records")
	}
	// Two insert-only writers racing the same identity must recheck under lock.
	results = make(chan error, 2)
	for range 2 {
		writers.Go(func() {
			results <- (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: provider, FailOnConflict: true}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "SHARED", Value: []byte("synthetic")}})
		})
	}
	writers.Wait()
	close(results)
	conflicts, successes := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if err == secure.ErrConflict {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if conflicts != 1 || successes != 1 {
		t.Fatal("insert collision was not rechecked under lock")
	}
}

func TestTransactionCrashChild(t *testing.T) {
	dir := os.Getenv("GO_TRANSACTION_CRASH_DIR")
	if dir == "" {
		return
	}
	phase := os.Getenv("GO_TRANSACTION_CRASH_PHASE")
	provider := &stub{dir: filepath.Join(dir, "provider"), backend: "libsecret"}
	err := (Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: provider}).apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("synthetic-crash-new")}}, transactionSteps{account: store.NewAccount, checkpoint: func(current string, index int) error {
		if current == phase {
			fmt.Println("ready")
			time.Sleep(30 * time.Second)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTransactionKilledWriterRecovery(t *testing.T) {
	transactionPlatform(t)
	for _, phase := range []string{"prepare", "publish", "published", "complete"} {
		t.Run(phase, func(t *testing.T) {
			dir, provider, prior := transactionFixture(t)
			path := filepath.Join(dir, "demo.keys")
			original, _ := os.ReadFile(path)
			cmd := exec.Command(os.Args[0], "-test.run=^TestTransactionCrashChild$")
			cmd.Env = append(os.Environ(), "GO_TRANSACTION_CRASH_DIR="+dir, "GO_TRANSACTION_CRASH_PHASE="+phase)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			ready := make(chan bool, 1)
			go func() { scanner := bufio.NewScanner(stdout); ready <- scanner.Scan() && scanner.Text() == "ready" }()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("crash child did not reach checkpoint")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("crash child checkpoint timed out")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			got, _ := os.ReadFile(path)
			published := phase == "published" || phase == "complete"
			if bytes.Equal(got, original) == published {
				t.Fatal("killed writer violated publication boundary")
			}
			if _, err := os.Stat(filepath.Join(dir, ".write-lock", "token")); err != nil {
				t.Fatal("killed writer lost ownership token")
			}
			intent, err := store.ReadRecovery(path, "libsecret")
			if err != nil || len(intent.Prepared) != 1 || len(intent.Obsolete) != 1 || intent.Obsolete[0].Account != prior[0].Account {
				t.Fatal("killed writer lost exact recovery candidates")
			}
			// This explicit test cleanup simulates the human-only lock removal
			// after owner verification. Production never steals a killed lock.
			if err := os.Remove(filepath.Join(dir, ".write-lock", "token")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(dir, ".write-lock")); err != nil {
				t.Fatal(err)
			}
			spy := &transactionSpy{stub: provider}
			transaction := Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy}
			if err := transaction.Apply([]store.Mutation{{Kind: store.MutationDelete, Key: "KEY"}}); err != secure.ErrRecovery || len(spy.calls) != 0 {
				t.Fatal("manual lock removal bypassed pending recovery")
			}
			if !published {
				value, err := provider.Get("secret/demo", prior[0].Account)
				defer secure.Clear(value)
				if err != nil || !bytes.Equal(value, []byte("synthetic-prior-KEY")) {
					t.Fatal("crash overwrote the prior account")
				}
			}
		})
	}
}

func TestTransactionReplaceOnly(t *testing.T) {
	transactionPlatform(t)
	dir, provider, _ := transactionFixture(t)
	spy := &transactionSpy{stub: provider}
	transaction := Transaction{SecretsDir: dir, Reference: "libsecret:demo", Provider: spy, RequireExisting: true}
	if err := transaction.Apply([]store.Mutation{{Kind: store.MutationPut, Key: "MISSING", Value: []byte("new")}}); err != secure.ErrNotFound || len(spy.calls) != 0 {
		t.Fatalf("missing rotation source: %v, provider calls: %d", err, len(spy.calls))
	}
	if err := transaction.Apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}); err != nil {
		t.Fatal(err)
	}
	transaction.FailOnConflict = true
	calls := len(spy.calls)
	if err := transaction.Apply([]store.Mutation{{Kind: store.MutationPut, Key: "KEY", Value: []byte("new")}}); err != secure.ErrInvalidRequest || len(spy.calls) != calls {
		t.Fatal("contradictory provider policies accepted")
	}
}
