//go:build windows

package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func TestWincredNativeLayout(t *testing.T) {
	var credential nativeCredential
	wantSize, wantBlob := uintptr(80), uintptr(40)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		wantSize, wantBlob = 52, 28
	}
	if unsafe.Sizeof(credential) != wantSize || unsafe.Offsetof(credential.blob) != wantBlob {
		t.Fatal("CREDENTIALW layout mismatch")
	}
	wide := []uint16{'a', 'b', 0}
	if !sameNativeTarget(&wide[0], wide) || sameNativeTarget(&wide[0], []uint16{'a', 0}) || sameNativeTarget(nil, wide) {
		t.Fatal("exact UTF-16 target comparison failed")
	}
}

// Explicitly gated hosted-CI tests only. Changing HOME cannot isolate CredMan:
// the only permitted real records are random synthetic exact targets journaled
// before writes, with both in-process and always-step exact cleanup.
func wincredCIJournal(t *testing.T) string {
	t.Helper()
	if os.Getenv("SECRET_REQUIRE_WINCRED") != "1" {
		t.Skip("isolated hosted Windows CredMan CI only")
	}
	root, journal := os.Getenv("RUNNER_TEMP"), os.Getenv("SECRET_WINCRED_TARGETS")
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" || !filepath.IsAbs(root) || journal != filepath.Join(root, "secret-wincred-targets.jsonl") {
		t.Fatal("required hosted Windows disposable-target journal missing")
	}
	return journal
}

func recordWincredTarget(t *testing.T, journal, target string) {
	t.Helper()
	file, err := os.OpenFile(journal, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("cannot record exact cleanup target")
	}
	err = json.NewEncoder(file).Encode(target)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal("cannot flush exact cleanup target")
	}
}

func cleanWincredTarget(target string) error {
	api := nativeWincred{}
	if err := api.delete(target); err != nil && !errors.Is(err, errWincredMissing) {
		return errors.New("exact cleanup delete failed")
	}
	record, err := api.read(target)
	releaseWincred(record)
	if !errors.Is(err, errWincredMissing) {
		return errors.New("exact cleanup absence not verified")
	}
	return nil
}

func TestWincredIntegration(t *testing.T) {
	journal := wincredCIJournal(t)
	p, err := newWincred()
	if err != nil {
		t.Fatal("required native CredMan API unavailable")
	}
	token, err := store.NewAccount()
	if err != nil {
		t.Fatal("cannot allocate synthetic target namespace")
	}
	service := "secret/m5a-ci-" + token
	accounts := []string{strings.Repeat("1", 32), strings.Repeat("2", 32), strings.Repeat("3", 32)}
	services := []string{service, service, service + "-adjacent"}
	values := [][]byte{{0xff, 0, '\n', '\r', 'x'}, {}, bytes.Repeat([]byte{0xff, 0, 'x', 'y', 'z'}, wincredBlobLimit/5)}
	for i, account := range accounts {
		target, ok := wincredTarget(services[i], account)
		if !ok {
			t.Fatal("invalid synthetic target")
		}
		// Never overwrite or register cleanup of an existing credential, even
		// on a random collision. Journal and cleanup precede the first write.
		record, err := (nativeWincred{}).read(target)
		releaseWincred(record)
		if !errors.Is(err, errWincredMissing) {
			t.Fatal("synthetic target is not absent")
		}
		recordWincredTarget(t, journal, target)
		t.Cleanup(func() {
			if cleanWincredTarget(target) != nil {
				t.Error("exact native target cleanup failed")
			}
		})
		if p.Put(services[i], account, services[i]+"/TOKEN", values[i]) != nil {
			t.Fatal("native synthetic put failed")
		}
		got, err := p.Get(services[i], account)
		matches := err == nil && bytes.Equal(got, values[i])
		secure.Clear(got)
		if !matches {
			t.Fatal("native raw blob round trip failed")
		}
	}
	// Replace only the first record, then delete it. Both adjacent targets survive.
	if p.Put(service, accounts[0], service+"/TOKEN", []byte("synthetic-replacement")) != nil {
		t.Fatal("native replacement failed")
	}
	got, err := p.Get(service, accounts[0])
	matches := err == nil && bytes.Equal(got, []byte("synthetic-replacement"))
	secure.Clear(got)
	if !matches {
		t.Fatal("native replacement readback failed")
	}
	if p.Put(service, accounts[0], service+"/TOKEN", make([]byte, wincredBlobLimit+1)) == nil {
		t.Fatal("oversize blob accepted")
	}
	if p.Delete(service, accounts[0]) != nil {
		t.Fatal("native delete failed")
	}
	if got, err := p.Get(service, accounts[0]); err == nil {
		secure.Clear(got)
		t.Fatal("deleted target returned")
	}
	for i := 1; i < len(accounts); i++ {
		got, err := p.Get(services[i], accounts[i])
		matches := err == nil && bytes.Equal(got, values[i])
		secure.Clear(got)
		if !matches {
			t.Fatal("adjacent target changed")
		}
	}
}

// The workflow runs this independently under always(), including when the native
// test process exits before its cleanup handlers. No enumeration or wildcards.
func TestWincredCleanup(t *testing.T) {
	journal := wincredCIJournal(t)
	data, err := os.ReadFile(journal)
	if os.IsNotExist(err) {
		return
	} // No write can precede a flushed journal entry.
	if err != nil || len(data) > 1<<20 {
		t.Fatal("cannot read exact cleanup journal")
	}
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
		var target string
		if json.Unmarshal(line, &target) != nil {
			t.Fatal("invalid exact cleanup journal")
		}
		// The service contains a slash: split at the final separator.
		index := strings.LastIndexByte(target, '/')
		if index < 0 {
			t.Fatal("invalid exact cleanup target")
		}
		service, account := target[:index], target[index+1:]
		expected, valid := wincredTarget(service, account)
		if !valid || expected != target || !strings.HasPrefix(service, "secret/m5a-ci-") {
			t.Fatal("unapproved cleanup namespace")
		}
		if cleanWincredTarget(target) != nil {
			t.Error("exact native cleanup or absence verification failed")
		}
	}
}
