//go:build windows

package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
	"golang.org/x/sys/windows"
)

func TestWindowsWincredTransaction(t *testing.T) {
	for _, phase := range []string{"success", "put", "readback", "mismatch", "publish", "locked publication", "published", "delete", "complete"} {
		t.Run(phase, func(t *testing.T) {
			dir := testutil.TempDir(t)
			path, _ := store.ManifestPath(dir, "wincred:synthetic")
			old := "11111111111111111111111111111111"
			fresh := "22222222222222222222222222222222"
			prior := []store.ManifestRecord{{Key: "TOKEN", Account: old}}
			if err := store.PublishManifestLocked(path, "wincred", prior); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			values := map[string][]byte{"secret/synthetic/" + old: []byte("synthetic-prior")}
			defer func() {
				for _, value := range values {
					secure.Clear(value)
				}
			}()
			calls := 0
			var owned [][]byte
			checkIntent := func() {
				t.Helper()
				calls++
				intent, err := store.ReadRecovery(path, "wincred")
				if err != nil || len(intent.Prepared) != 1 || len(intent.Obsolete) != 1 || intent.Prepared[0].Account != fresh || intent.Obsolete[0].Account != old {
					t.Fatal("provider access before exact private recovery intent")
				}
			}
			api := fakeWincredAPI{
				writeCall: func(target string, blob []byte) error {
					checkIntent()
					owned = append(owned, blob)
					if target != "secret/synthetic/"+fresh {
						t.Fatal("transaction reused an account")
					}
					if phase == "put" {
						return errors.New("synthetic-failure")
					}
					values[target] = secure.Clone(blob)
					return nil
				},
				readCall: func(target string) (*wincredRecord, error) {
					checkIntent()
					if phase == "readback" {
						return nil, errors.New("synthetic-failure")
					}
					blob := secure.Clone(values[target])
					if phase == "mismatch" && len(blob) > 0 {
						blob[0] ^= 1
					}
					owned = append(owned, blob)
					return &wincredRecord{kind: wincredGeneric, target: target, blob: blob, size: uint32(len(blob)), release: func() {}}, nil
				},
				deleteCall: func(target string) error {
					checkIntent()
					records, err := store.ReadManifest(path, "wincred")
					if err != nil || len(records) != 1 || records[0].Account != fresh || target != "secret/synthetic/"+old {
						t.Fatal("cleanup before publication or wrong target")
					}
					if phase == "delete" {
						return errors.New("synthetic-failure")
					}
					secure.Clear(values[target])
					delete(values, target)
					return nil
				},
			}
			var locked windows.Handle
			if phase == "locked publication" {
				wide, err := windows.UTF16PtrFromString(path)
				if err != nil {
					t.Fatal(err)
				}
				locked, err = windows.CreateFile(wide, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
				if err != nil {
					t.Fatal("cannot lock disposable manifest")
				}
				defer windows.CloseHandle(locked)
			}
			transaction := Transaction{SecretsDir: dir, Reference: "wincred:synthetic", Provider: wincred{api: api}, RequireExisting: true}
			input := []byte("synthetic-replacement")
			mutations := []store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: input}}
			err = transaction.apply(mutations, transactionSteps{account: func() (string, error) { return fresh, nil }, checkpoint: func(current string, _ int) error {
				if current == phase {
					return errors.New("synthetic-checkpoint")
				}
				return nil
			}})
			if phase == "success" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.ReadRecovery(path, "wincred"); !os.IsNotExist(err) {
					t.Fatal("success left recovery")
				}
				if _, exists := values["secret/synthetic/"+old]; exists {
					t.Fatal("obsolete account survived cleanup")
				}
			} else {
				if err != secure.ErrRecovery {
					t.Fatalf("failure returned %v, want fixed recovery", err)
				}
				body, err := os.ReadFile(path + ".recovery")
				if err != nil || bytes.Contains(body, input) || bytes.Contains(body, []byte("synthetic-prior")) {
					t.Fatal("recovery lost names-only contract")
				}
				before := calls
				if transaction.Apply(mutations) != secure.ErrRecovery || calls != before {
					t.Fatal("pending recovery reached provider")
				}
			}
			published := phase == "success" || phase == "published" || phase == "delete" || phase == "complete"
			body, err := os.ReadFile(path)
			if err != nil || bytes.Equal(body, original) == published {
				t.Fatal("publication boundary violated")
			}
			for _, value := range owned {
				if !bytes.Equal(value, make([]byte, len(value))) {
					t.Fatal("owned transport bytes retained")
				}
			}
			if !bytes.Equal(input, []byte("synthetic-replacement")) {
				t.Fatal("borrowed input changed")
			}
			for _, name := range []string{".write-lock", ".secret-stash.*"} {
				matches, err := filepath.Glob(filepath.Join(dir, name))
				if err != nil || len(matches) != 0 {
					t.Fatal("transaction leaked lock or scratch")
				}
			}
		})
	}
}

// Real native transaction coverage stays under the existing isolated-target gate.
// The API wrapper journals and registers cleanup before each fresh-account write.
type journalWincredAPI struct {
	t          *testing.T
	journal    string
	failDelete bool
}

func (api *journalWincredAPI) read(target string) (*wincredRecord, error) {
	return (nativeWincred{}).read(target)
}
func (api *journalWincredAPI) write(target string, blob []byte) error {
	record, err := (nativeWincred{}).read(target)
	releaseWincred(record)
	if !errors.Is(err, errWincredMissing) {
		api.t.Fatal("fresh synthetic account already exists")
	}
	recordWincredTarget(api.t, api.journal, target)
	api.t.Cleanup(func() {
		if cleanWincredTarget(target) != nil {
			api.t.Error("transaction exact native cleanup failed")
		}
	})
	return (nativeWincred{}).write(target, blob)
}
func (api *journalWincredAPI) delete(target string) error {
	if api.failDelete {
		return errors.New("synthetic cleanup failure")
	}
	return (nativeWincred{}).delete(target)
}

func TestWincredTransactionIntegration(t *testing.T) {
	journal := wincredCIJournal(t)
	for _, phase := range []string{"success", "publish", "delete"} {
		t.Run(phase, func(t *testing.T) {
			token, err := store.NewAccount()
			if err != nil {
				t.Fatal(err)
			}
			reference := "wincred:m5a-ci-" + token
			dir := testutil.TempDir(t)
			api := &journalWincredAPI{t: t, journal: journal}
			transaction := Transaction{SecretsDir: dir, Reference: reference, Provider: wincred{api: api}}
			put := []store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("synthetic-native-prior")}}
			if err := transaction.Apply(put); err != nil {
				t.Fatal(err)
			}
			path, _ := store.ManifestPath(dir, reference)
			before, err := store.ReadManifest(path, "wincred")
			if err != nil || len(before) != 1 {
				t.Fatal("initial native publication failed")
			}
			put[0].Value = []byte("synthetic-native-replacement")
			api.failDelete = phase == "delete"
			err = transaction.apply(put, transactionSteps{account: store.NewAccount, checkpoint: func(current string, _ int) error {
				if phase == "publish" && current == "publish" {
					return errors.New("synthetic publication failure")
				}
				return nil
			}})
			want := error(nil)
			if phase != "success" {
				want = secure.ErrRecovery
			}
			if err != want {
				t.Fatalf("native transaction returned %v", err)
			}
			after, err := store.ReadManifest(path, "wincred")
			if err != nil || len(after) != 1 {
				t.Fatal("native manifest lost")
			}
			if (after[0].Account == before[0].Account) != (phase == "publish") {
				t.Fatal("native fresh-account publication boundary violated")
			}
			_, _, service, _ := DispatchWith(reference, transaction.Provider)
			got, err := transaction.Provider.Get(service, after[0].Account)
			defer secure.Clear(got)
			value := put[0].Value
			if phase == "publish" {
				value = []byte("synthetic-native-prior")
			}
			if err != nil || !bytes.Equal(got, value) {
				t.Fatal("native transaction readback changed bytes")
			}
			intent, err := store.ReadRecovery(path, "wincred")
			if phase == "success" {
				if !os.IsNotExist(err) {
					t.Fatal("native success left recovery")
				}
			} else if err != nil || len(intent.Prepared) != 1 || len(intent.Obsolete) != 1 {
				t.Fatal("native failure lost exact recovery")
			}
		})
	}
}
