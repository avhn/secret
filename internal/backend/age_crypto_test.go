package backend

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func ageTestConfig(t *testing.T) (AgeConfig, string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("age filesystem intentionally unavailable")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".secrets")
	keys := filepath.Join(dir, ".age-keys")
	if os.MkdirAll(keys, 0700) != nil {
		t.Fatal("mkdir")
	}
	config := AgeConfig{Home: home, SecretsDir: dir, IdentityFile: filepath.Join(keys, "identity")}
	recipients := filepath.Join(keys, "recipients")
	ageTestKey(t, config.IdentityFile, recipients)
	return config, "age:test", recipients
}
func ageTestKey(t *testing.T, identity, recipients string) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("generate identity")
	}
	data := []byte(id.String() + "\n")
	defer secure.Clear(data)
	if os.WriteFile(identity, data, 0600) != nil || os.WriteFile(recipients, []byte(id.Recipient().String()+"\n"), 0600) != nil {
		t.Fatal("key fixtures")
	}
	return id
}
func TestAgeCryptoLifecycle(t *testing.T) {
	config, reference, recipients := ageTestConfig(t)
	if err := config.Init(reference, recipients); err != nil {
		t.Fatal(err)
	}
	value := []byte("SYNTHETIC-AGE-SENTINEL")
	defer secure.Clear(value)
	transaction := AgeTransaction{Config: config, Reference: reference}
	put := []store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: value}}
	if err := transaction.Apply(put); err != nil {
		t.Fatal(err)
	}
	snapshot, err := config.Read(reference)
	if err != nil {
		t.Fatal(err)
	}
	account := snapshot.Envelope.Records[0].Account
	if len(snapshot.Records) != 1 || !bytes.Equal(snapshot.Records[0].Value, value) {
		t.Fatal("round trip")
	}
	snapshot.Close()
	for _, mutations := range [][]store.Mutation{
		{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("replacement")}},
		{{Kind: store.MutationRename, Key: "TOKEN", NewKey: "RENAMED"}},
	} {
		if err := transaction.Apply(mutations); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err = config.Read(reference)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Envelope.Records[0].Account != account {
		t.Fatal("unstable account")
	}
	snapshot.Close()
	path, _ := store.AgePath(config.SecretsDir, reference)
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(old, value) || bytes.Contains(old, []byte("replacement")) {
		t.Fatal("plaintext persistence")
	}
	newIdentity := filepath.Join(filepath.Dir(config.IdentityFile), "new-identity")
	newRecipients := filepath.Join(filepath.Dir(recipients), "new-recipients")
	ageTestKey(t, newIdentity, newRecipients)
	if err := config.Rekey(reference, newRecipients, newIdentity); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := config.Read(reference); err == nil {
		snapshot.Close()
		t.Fatal("removed key accepted")
	}
	newConfig := config
	newConfig.IdentityFile = newIdentity
	snapshot, err = newConfig.Read(reference)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Envelope.Records[0].Account != account {
		t.Fatal("rekey account")
	}
	snapshot.Close()
	oldIDs, _, err := config.keyFile(config.IdentityFile, true)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err = decryptAge(old, oldIDs)
	if err != nil {
		t.Fatal("old ciphertext unexpectedly unreadable")
	}
	snapshot.Close()
	if err := config.Init(reference, recipients); err != secure.ErrConflict {
		t.Fatal("init overwrote")
	}
	if err := (AgeTransaction{Config: newConfig, Reference: reference}).Apply([]store.Mutation{{Kind: store.MutationDelete, Key: "RENAMED"}}); err != nil {
		t.Fatal(err)
	}
}
func TestAgeRecipientIdentityMatrix(t *testing.T) {
	first, _ := age.GenerateX25519Identity()
	second, _ := age.GenerateX25519Identity()
	wrong, _ := age.GenerateX25519Identity()
	recipients := []string{first.Recipient().String(), second.Recipient().String()}
	for _, id := range []*age.X25519Identity{first, second} {
		candidate, err := encryptAge(nil, nil, recipients, []age.Identity{id}, ageSteps{})
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range []*age.X25519Identity{first, second} {
			snapshot, err := decryptAge(candidate, []age.Identity{match})
			if err != nil {
				t.Fatal(err)
			}
			snapshot.Close()
		}
		if snapshot, err := decryptAge(candidate, []age.Identity{wrong}); err == nil {
			snapshot.Close()
			t.Fatal("wrong identity")
		}
		for _, corrupt := range [][]byte{append(append([]byte(nil), candidate...), 0), candidate[:len(candidate)-1]} {
			if snapshot, err := decryptAge(corrupt, []age.Identity{id}); err == nil {
				snapshot.Close()
				t.Fatal("trailing or truncated stream")
			}
		}
	}
}
func TestAgeRejectedStanzas(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	candidate, err := encryptAge(nil, nil, []string{id.Recipient().String()}, []age.Identity{id}, ageSteps{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"scrypt", "ssh-ed25519", "plugin", "X25519MLKEM768", "unknown"} {
		bad := bytes.Replace(candidate, []byte("-> X25519 "), []byte("-> "+kind+" "), 1)
		if snapshot, err := decryptAge(bad, []age.Identity{id}); err == nil {
			snapshot.Close()
			t.Fatal("unsupported stanza")
		}
	}
}
func TestAgeCryptoFailuresPreserveOld(t *testing.T) {
	config, reference, recipients := ageTestConfig(t)
	if err := config.Init(reference, recipients); err != nil {
		t.Fatal(err)
	}
	path, _ := store.AgePath(config.SecretsDir, reference)
	before, _ := os.ReadFile(path)
	for _, phase := range []string{"encrypt-close", "candidate-verify"} {
		transaction := AgeTransaction{Config: config, Reference: reference}
		err := transaction.apply([]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("SYNTHETIC-FAULT-VALUE")}}, ageSteps{checkpoint: func(at string) error {
			if at == phase {
				return errors.New("injected")
			}
			return nil
		}})
		after, _ := os.ReadFile(path)
		if err == nil || !bytes.Equal(before, after) {
			t.Fatal("failed crypto published")
		}
	}
	wrong := filepath.Join(filepath.Dir(config.IdentityFile), "wrong")
	wrongRecipients := wrong + "-recipients"
	ageTestKey(t, wrong, wrongRecipients)
	if err := config.Rekey(reference, wrongRecipients, config.IdentityFile); err == nil {
		t.Fatal("unproven candidate")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed rekey changed bytes")
	}
}
func TestAgeConcurrentWritersReaders(t *testing.T) {
	config, reference, recipients := ageTestConfig(t)
	if err := config.Init(reference, recipients); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			transaction := AgeTransaction{Config: config, Reference: reference}
			err := transaction.Apply([]store.Mutation{{Kind: store.MutationPut, Key: fmt.Sprintf("KEY_%d", i), Value: []byte("synthetic")}})
			if err != nil {
				failures <- err
				return
			}
			snapshot, err := config.Read(reference)
			if err != nil {
				failures <- err
			} else {
				snapshot.Close()
			}
		}(i)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	snapshot, err := config.Read(reference)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	if len(snapshot.Records) != 8 {
		t.Fatal("lost update")
	}
}
func TestAgeKeyFiles(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	valid := []byte(id.String() + "\n")
	defer secure.Clear(valid)
	if ids, _, err := parseAgeKeyLines(valid, true); err != nil || len(ids) != 1 {
		t.Fatal("identity")
	}
	for _, data := range [][]byte{nil, []byte("AGE-SECRET-KEY-INVALID\n"), bytes.Repeat([]byte("#"), maxAgeKeyFile+1), append(append([]byte(nil), valid...), valid...)} {
		if _, _, err := parseAgeKeyLines(data, true); err == nil {
			t.Fatal("accepted key file")
		}
	}
	config, _, _ := ageTestConfig(t)
	outside := filepath.Join(config.Home, "outside")
	if _, _, err := config.keyFile(outside, true); err == nil {
		t.Fatal("escaped namespace")
	}
	if os.Chmod(config.IdentityFile, 0644) != nil {
		t.Fatal("chmod")
	}
	if _, _, err := config.keyFile(config.IdentityFile, true); err == nil {
		t.Fatal("insecure identity")
	}
}
func TestAgeWindowsRejectsBeforeAccess(t *testing.T) {
	if runtime.GOOS != "windows" {
		return
	}
	config := AgeConfig{Home: "missing", SecretsDir: "missing", IdentityFile: "missing"}
	if err := config.Init("age:test", "missing"); err != secure.ErrUnsupported {
		t.Fatal(err)
	}
	if err := config.Rekey("age:test", "missing", "missing"); err != secure.ErrUnsupported {
		t.Fatal(err)
	}
	if _, err := config.Read("age:test"); err != secure.ErrUnsupported {
		t.Fatal(err)
	}
	if err := (AgeTransaction{Config: config, Reference: "age:test"}).Apply(nil); err != secure.ErrUnsupported {
		t.Fatal(err)
	}
}
