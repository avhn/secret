package store

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/avhn/secret/internal/secure"
)

func ageFixture(t *testing.T) ([]byte, []ManifestRecord, []byte) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("generate")
	}
	records := []ManifestRecord{{Key: "TOKEN", Labels: map[string]string{}, Account: "0123456789abcdef0123456789abcdef"}}
	prefix, err := EncodeAgePrefix([]string{id.Recipient().String()}, records)
	if err != nil {
		t.Fatal(err)
	}
	return prefix, records, []byte("TOKEN=synthetic-value\n")
}
func TestAgeCodec(t *testing.T) {
	prefix, records, dotenv := ageFixture(t)
	payload, err := EncodeAgePayload(prefix, dotenv, records)
	if err != nil {
		t.Fatal(err)
	}
	defer secure.Clear(payload)
	envelope := append(append([]byte(nil), prefix...), []byte("age-encryption.org/v1\nfixture")...)
	parsed, err := ParseAgeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeAgePayload(parsed, payload)
	defer secure.Clear(got)
	if err != nil || !bytes.Equal(got, dotenv) {
		t.Fatal("payload round trip")
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil}, {"version", []byte("secret-age-store-v2\n")}, {"truncated", prefix[:len(prefix)-1]},
		{"armor", append(append([]byte(nil), prefix...), []byte("-----BEGIN AGE ENCRYPTED FILE-----")...)},
		{"bound", make([]byte, MaxAgeFile+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAgeEnvelope(tc.data); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	damaged := append([]byte(nil), envelope...)
	binary.BigEndian.PutUint32(damaged[len(AgeMagic):], ^uint32(0))
	if _, err := ParseAgeEnvelope(damaged); err == nil {
		t.Fatal("overflow")
	}
	for _, bad := range [][]byte{append(append([]byte(nil), payload...), 0), payload[:len(payload)-1]} {
		if _, err := DecodeAgePayload(parsed, bad); err == nil {
			t.Fatal("payload framing")
		}
	}
	payload[len(agePayloadMagic)] ^= 1
	if _, err := DecodeAgePayload(parsed, payload); err == nil {
		t.Fatal("binding")
	}
	if ValidateAgePlaintext([]byte("TOKEN=a\nTOKEN=b\n"), records) == nil {
		t.Fatal("duplicate")
	}
	if ValidateAgePlaintext([]byte("OTHER=a\n"), records) == nil {
		t.Fatal("inventory drift")
	}
}
func TestAgeRecipients(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	valid := id.Recipient().String()
	for _, recipients := range [][]string{nil, {valid, valid}, {"ssh-ed25519 invalid"}, {"age1invalid"}, {"AGE1INVALID"}} {
		if _, err := CanonicalAgeRecipients(recipients); err == nil {
			t.Fatal("accepted recipients")
		}
	}
	if _, err := CanonicalAgeRecipients([]string{valid}); err != nil {
		t.Fatal(err)
	}
}
func TestAgeAnchoredTransactions(t *testing.T) {
	t.Cleanup(SetLockWaitForTest(30 * time.Second))
	if runtime.GOOS == "windows" {
		if err := WithAgeLock("missing", false, func(*AgeEditor) error { t.Fatal("opened"); return nil }); err != secure.ErrUnsupported {
			t.Fatal(err)
		}
		return
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "test.secret.age")
	prefix, _, _ := ageFixture(t)
	ciphertext := append(prefix, []byte("age-encryption.org/v1\nfixture")...)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- WithAgeLock(path, true, func(e *AgeEditor) error { return e.Publish(ciphertext) })
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if err == secure.ErrConflict {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatal("concurrent create")
	}
	before, _ := os.ReadFile(path)
	if err := WithAgeLock(path, true, func(*AgeEditor) error { t.Fatal("existing opened"); return nil }); err != secure.ErrConflict {
		t.Fatal(err)
	}
	for _, phase := range []string{"scratch-write", "file-sync", "rename", "directory-sync"} {
		t.Run(phase, func(t *testing.T) {
			replacement := append(append([]byte(nil), ciphertext...), byte('x'))
			err := withAgeLock(path, false, func(e *AgeEditor) error { return e.Publish(replacement) }, func(at string) error {
				if at == phase {
					return errors.New("injected")
				}
				return nil
			})
			after, _ := os.ReadFile(path)
			if phase == "directory-sync" {
				if err != ErrAgeDurability || !bytes.Equal(after, replacement) {
					t.Fatal("uncertain publication")
				}
			} else if err == nil || !bytes.Equal(before, after) {
				t.Fatal("old bytes changed")
			}
		})
	}
	if err := WithAgeLock(filepath.Join(dir, "missing.secret.age"), false, func(*AgeEditor) error { t.Fatal("missing opened"); return nil }); err == nil {
		t.Fatal("missing")
	}
}
func TestAgePrivatePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "key")
	os.WriteFile(path, []byte("synthetic"), 0600)
	if _, err := ReadPrivateAgeFile(path, 64); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0644)
	if _, err := ReadPrivateAgeFile(path, 64); err == nil {
		t.Fatal("public key file")
	}
	os.Chmod(path, 0600)
	alias := filepath.Join(dir, "alias")
	os.Symlink(path, alias)
	if _, err := ReadPrivateAgeFile(alias, 64); err == nil {
		t.Fatal("final symlink")
	}
	nested := filepath.Join(dir, "nested")
	os.Symlink(dir, nested)
	if _, err := ReadPrivateAgeFile(filepath.Join(nested, "key"), 64); err == nil {
		t.Fatal("ancestor symlink")
	}
	os.Chmod(dir, 0755)
	if _, err := ReadPrivateAgeFile(path, 64); err == nil {
		t.Fatal("public directory")
	}
}
