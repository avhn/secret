package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
)

func TestFileTransactionBytes(t *testing.T) {
	labels := map[string]string{"env": "dev"}
	for _, tc := range []struct {
		name, source, want string
		mutations          []Mutation
	}{
		{"rotate framing", "# keep\r\n  export KEY='old'\r\nNEXT=peer\n", "# keep\r\n  export KEY=new\r\nNEXT=peer\n", []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("new")}}},
		{"delete exact scope", "KEY=flat\n[env=dev]\nKEY=dev\n# keep\n[env=prod]\nKEY=prod", "KEY=flat\n[env=dev]\n# keep\n[env=prod]\nKEY=prod", []Mutation{{Kind: MutationDelete, Key: "KEY", Labels: labels}}},
		{"rename original spelling", "# keep\n  export KEY=\"x$#=\\\"\r\nKEY='last'", "# keep\n  export NEW=\"x$#=\\\"\r\nNEW='last'", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "NEW"}}},
		{"rotate duplicates", "KEY=first\n# peer\nKEY=last\n", "# peer\nKEY=new\n", []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("new")}}},
		{"malformed untouched", "KEY='unterminated\nOTHER=peer\nKEY=old", "KEY='unterminated\nOTHER=peer\nKEY='edge\"'", []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("edge\"")}}},
		{"new scope", "# keep\nKEY=old", "# keep\nKEY=old\n[env=dev]\nNEW=new\n", []Mutation{{Kind: MutationPut, Key: "NEW", Labels: labels, Value: []byte("new")}}},
		{"flat insertion", "# keep\n[env=dev]\nKEY=dev", "# keep\nNEW=new\n[env=dev]\nKEY=dev", []Mutation{{Kind: MutationPut, Key: "NEW", Value: []byte("new")}}},
		{"batch", "KEY=old\nOTHER=peer\nREMOVE=gone\n", "NEW=old\nOTHER=updated\nADDED=added\n", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "NEW"}, {Kind: MutationPut, Key: "OTHER", Value: []byte("updated")}, {Kind: MutationDelete, Key: "REMOVE"}, {Kind: MutationPut, Key: "ADDED", Value: []byte("added\n")}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.TempDir(t)
			path := filepath.Join(dir, "synthetic.store")
			if err := testutil.WriteFile(path, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			transaction := FileTransaction{SecretsDir: dir, Path: path}
			if err := transaction.Apply(tc.mutations); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			defer secure.Clear(got)
			if err != nil || !bytes.Equal(got, []byte(tc.want)) {
				t.Fatalf("unaffected-byte golden mismatch: %v", err)
			}
			assertPrivateFixture(t, path)
		})
	}
}

func TestMutationValidation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutations []Mutation
		want      error
	}{
		{"empty", nil, secure.ErrInvalidRequest},
		{"invalid kind", []Mutation{{Kind: "other", Key: "KEY"}}, secure.ErrInvalidRequest},
		{"invalid key", []Mutation{{Kind: MutationDelete, Key: "bad-key"}}, secure.ErrInvalidRequest},
		{"invalid label", []Mutation{{Kind: MutationDelete, Key: "KEY", Labels: map[string]string{"env": "bad value"}}}, secure.ErrInvalidRequest},
		{"invalid value", []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("bad\nvalue")}}, secure.ErrInvalidRequest},
		{"unexpected destination", []Mutation{{Kind: MutationPut, Key: "KEY", NewKey: "OTHER", Value: []byte("valid")}}, secure.ErrInvalidRequest},
		{"unexpected value", []Mutation{{Kind: MutationDelete, Key: "KEY", Value: []byte("valid")}}, secure.ErrInvalidRequest},
		{"delete destination", []Mutation{{Kind: MutationDelete, Key: "KEY", NewKey: "OTHER"}}, secure.ErrInvalidRequest},
		{"invalid destination", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "bad-key"}}, secure.ErrInvalidRequest},
		{"same name", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "KEY"}}, secure.ErrConflict},
		{"duplicate source", []Mutation{{Kind: MutationDelete, Key: "KEY"}, {Kind: MutationDelete, Key: "KEY"}}, secure.ErrConflict},
		{"destination overlaps source", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "OTHER"}, {Kind: MutationDelete, Key: "OTHER"}}, secure.ErrConflict},
		{"source overlaps destination", []Mutation{{Kind: MutationDelete, Key: "OTHER"}, {Kind: MutationRename, Key: "KEY", NewKey: "OTHER"}}, secure.ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateMutations(tc.mutations); !errors.Is(err, tc.want) {
				t.Fatalf("validation = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFileTransactionPrepublicationFailures(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mutations []Mutation
		insert    bool
		want      error
	}{
		{"missing delete", []Mutation{{Kind: MutationDelete, Key: "ABSENT"}}, false, secure.ErrNotFound},
		{"missing rename", []Mutation{{Kind: MutationRename, Key: "ABSENT", NewKey: "NEW"}}, false, secure.ErrNotFound},
		{"rename collision", []Mutation{{Kind: MutationRename, Key: "KEY", NewKey: "OTHER"}}, false, secure.ErrConflict},
		{"insert collision", []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("new")}}, true, secure.ErrConflict},
		{"late batch conflict", []Mutation{{Kind: MutationPut, Key: "NEW", Value: []byte("new")}, {Kind: MutationDelete, Key: "ABSENT"}}, false, secure.ErrNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.TempDir(t)
			path := filepath.Join(dir, "synthetic.store")
			original := []byte("# keep\nKEY=old\nOTHER=peer\n")
			if err := testutil.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			err := (FileTransaction{SecretsDir: dir, Path: path, FailOnConflict: tc.insert}).Apply(tc.mutations)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatal("pre-publication failure changed the previous file")
			}
		})
	}
}

func TestFileTransactionTargetsAndPreflight(t *testing.T) {
	dir := testutil.TempDir(t)
	mutations := []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("new")}}
	for _, name := range []string{"directory", "symlink"} {
		path := filepath.Join(dir, name)
		if name == "directory" {
			if err := testutil.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Symlink("directory", path); err != nil {
			t.Fatal(err)
		}
		if err := (FileTransaction{SecretsDir: dir, Path: path}).Apply(mutations); err != secure.ErrTransaction {
			t.Fatalf("unsafe %s target: %v", name, err)
		}
	}
	missing := filepath.Join(dir, "must-not-exist")
	if err := (FileTransaction{SecretsDir: missing, Path: filepath.Join(missing, "store")}).Apply([]Mutation{{Kind: MutationPut, Key: "INVALID-KEY"}}); err != secure.ErrInvalidRequest {
		t.Fatal("invalid request did not fail preflight")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("invalid request touched storage")
	}
	if err := (FileTransaction{SecretsDir: dir, Path: "relative"}).Apply(mutations); err != secure.ErrInvalidRequest {
		t.Fatal("relative transaction target accepted")
	}
}

func TestFileTransactionChild(t *testing.T) {
	path := os.Getenv("GO_MUTATION_CHILD_PATH")
	if path == "" {
		return
	}
	t.Cleanup(SetLockWaitForTest(30 * time.Second))
	key := os.Getenv("GO_MUTATION_CHILD_KEY")
	if err := (FileTransaction{SecretsDir: filepath.Dir(path), Path: path, FailOnConflict: true}).Apply([]Mutation{{Kind: MutationPut, Key: key, Value: []byte("synthetic")}}); err != nil {
		t.Fatal(err)
	}
}

func TestFileTransactionConcurrentWriters(t *testing.T) {
	t.Cleanup(SetLockWaitForTest(30 * time.Second))
	for _, subprocess := range []bool{false, true} {
		t.Run(fmt.Sprint("process-", subprocess), func(t *testing.T) {
			dir := testutil.TempDir(t)
			path := filepath.Join(dir, "synthetic.store")
			const count = 4
			results := make(chan error, count)
			var writers sync.WaitGroup
			for i := range count {
				writers.Go(func() {
					key := fmt.Sprintf("KEY_%d", i)
					if subprocess {
						cmd := exec.Command(os.Args[0], "-test.run=^TestFileTransactionChild$")
						cmd.Env = append(os.Environ(), "GO_MUTATION_CHILD_PATH="+path, "GO_MUTATION_CHILD_KEY="+key)
						results <- cmd.Run()
					} else {
						results <- (FileTransaction{SecretsDir: dir, Path: path, FailOnConflict: true}).Apply([]Mutation{{Kind: MutationPut, Key: key, Value: []byte("synthetic")}})
					}
				})
			}
			writers.Wait()
			close(results)
			for err := range results {
				if err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			records, warnings := ParseMetadata(data)
			if len(records) != count || len(warnings) != 0 {
				t.Fatal("concurrent transaction lost records")
			}
		})
	}
}

func FuzzFileMutationRoundTrip(f *testing.F) {
	for _, value := range [][]byte{[]byte("plain"), []byte("edge'"), []byte("\"edge"), []byte{0xff, 0xfe}, []byte("a=b$#\\")} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		normalized, err := NormalizeValue(value)
		if err != nil {
			return
		}
		defer secure.Clear(normalized)
		source := []byte("# keep\r\n  export KEY=prior\r\nPEER=unchanged")
		result, err := rewriteMutation(source, Mutation{Kind: MutationPut, Key: "KEY", Value: value})
		if err != nil {
			t.Fatal(err)
		}
		defer secure.Clear(result)
		records, _ := Parse(result)
		defer func() {
			for _, record := range records {
				secure.Clear(record.Value)
			}
		}()
		if len(records) != 2 || !bytes.Equal(records[0].Value, normalized) || !bytes.HasSuffix(result, []byte("\r\nPEER=unchanged")) || !bytes.HasPrefix(result, []byte("# keep\r\n  export KEY=")) {
			t.Fatal("mutation violated round-trip or unaffected bytes")
		}
	})
}

func TestMutationNamesOnlyPreflight(t *testing.T) {
	records := []MetadataRecord{{Key: "KEY", Labels: map[string]string{"env": "dev"}}}
	// No dummy value or source-provider fetch is needed to preflight a put.
	mutation := []Mutation{{Kind: MutationPut, Key: "KEY", Labels: map[string]string{"env": "dev"}}}
	if err := CheckMutationConflicts(records, mutation, true, false); err != secure.ErrConflict {
		t.Fatalf("names-only collision: %v", err)
	}
	if err := CheckMutationConflicts(records, mutation, false, true); err != nil {
		t.Fatalf("names-only rotation: %v", err)
	}
	if err := CheckMutationConflicts(nil, mutation, false, true); err != secure.ErrNotFound {
		t.Fatalf("missing rotation source: %v", err)
	}
	if err := CheckMutationConflicts(nil, mutation, true, false); err != nil {
		t.Fatalf("names-only insertion: %v", err)
	}
	if err := ValidateMutations(mutation); err != secure.ErrInvalidRequest {
		t.Fatal("Apply validation accepted a missing put value")
	}
	if err := CheckMutationConflicts(records, mutation, true, true); err != secure.ErrInvalidRequest {
		t.Fatal("contradictory transaction policies accepted")
	}
}

func TestFileTransactionReplaceOnly(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.store")
	transaction := FileTransaction{SecretsDir: dir, Path: path, RequireExisting: true}
	mutations := []Mutation{{Kind: MutationPut, Key: "KEY", Value: []byte("new")}}
	if err := transaction.Apply(mutations); err != secure.ErrNotFound {
		t.Fatalf("missing rotation: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("replace-only put created a missing file")
	}
	if err := testutil.WriteFile(path, []byte("KEY=prior\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := transaction.Apply(mutations); err != nil {
		t.Fatal(err)
	}
	transaction.FailOnConflict = true
	if err := transaction.Apply(mutations); err != secure.ErrInvalidRequest {
		t.Fatal("contradictory file policies accepted")
	}
}
