package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/secret/internal/store"
)

// stub is deliberately compiled only into tests. Production dispatch cannot
// activate it through SECRET_BACKEND_STUB_DIR or other environment variables.
type stub struct {
	dir, backend     string
	getFail, putFail bool
}

func (s *stub) log(op, service, account string) {
	backend := s.backend
	if backend == "" {
		backend = "keychain"
	}
	f, _ := os.OpenFile(filepath.Join(s.dir, "log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if f != nil {
		_, _ = f.WriteString(op + " " + backend + ":" + strings.TrimPrefix(service, "secret/") + " " + account + "\n")
		_ = f.Close()
	}
}
func (s *stub) path(service, account string) string {
	backend := s.backend
	if backend == "" {
		backend = "keychain"
	}
	return filepath.Join(s.dir, backend, service, account)
}
func (s *stub) Get(service, account string) ([]byte, error) {
	s.log("get", service, account)
	if s.getFail {
		return nil, errors.New("stub get failure")
	}
	info, err := os.Lstat(s.path(service, account))
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("stub lookup failure")
	}
	return os.ReadFile(s.path(service, account))
}
func (s *stub) Put(service, account, label string, value []byte) error {
	s.log("put", service, account)
	if s.putFail {
		return errors.New("stub put failure")
	}
	path := s.path(service, account)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, value, 0600)
}
func (s *stub) Delete(service, account string) error { return os.Remove(s.path(service, account)) }

func TestDispatch(t *testing.T) {
	for _, ref := range []string{"keychain:demo", "libsecret:other"} {
		p, b, service, err := Dispatch(ref)
		if err != nil || b != strings.Split(ref, ":")[0] || service != "secret/"+strings.Split(ref, ":")[1] {
			t.Errorf("dispatch %s: %v", ref, err)
		}
		switch b {
		case "libsecret":
			if _, ok := p.(libsecret); !ok {
				t.Error("libsecret provider not selected")
			}
		case "keychain":
			if _, ok := p.(keychain); !ok {
				t.Error("keychain provider not selected")
			}
		}
	}
	for _, ref := range []string{"keychain:../other", "libsecret:", "file:demo"} {
		if _, _, _, err := Dispatch(ref); err == nil {
			t.Errorf("accepted %s", ref)
		}
	}
}
func TestBackendOrdering(t *testing.T) {
	// Inventory mapping: stash, reuse, reused_id, backend_value, no_backend_calls,
	// put_failure, no_manifest, manifest_failure, no_published_record,
	// orphan_exists, failed_publish_existing, prior_record_intact, mismatch.
	dir := t.TempDir()
	s := &stub{dir: filepath.Join(dir, "stub")}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(dir, "demo.keys")
	if err := Stash(dir, "libsecret:other", "FAIL", nil, []byte("synthetic-failure"), &stub{dir: s.dir, backend: "libsecret", putFail: true}); err == nil {
		t.Error("put failure accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "other.keys")); !os.IsNotExist(err) {
		t.Error("put failure published manifest")
	}
	if err := stashWithPublish(dir, "libsecret:other", "FAIL", nil, []byte("synthetic-failure"), &stub{dir: s.dir, backend: "libsecret"}, func(string, string, string, map[string]string, string) error {
		return errors.New("synthetic publish failure")
	}); err == nil {
		t.Error("publish failure accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "other.keys")); !os.IsNotExist(err) {
		t.Error("publish failure created manifest")
	}
	orphan, err := os.ReadDir(filepath.Join(s.dir, "libsecret", "secret", "other"))
	if err != nil || len(orphan) != 1 {
		t.Error("new record orphan missing")
	}
	value := []byte("synthetic-dev")
	if err := Stash(dir, "keychain:demo", "TOKEN", map[string]string{"env": "dev"}, value, s); err != nil {
		t.Fatal(err)
	}
	records, err := ListNames(dir, "keychain:demo")
	if err != nil || len(records) != 1 {
		t.Fatalf("published names = %d, %v", len(records), err)
	}
	account := records[0].Account
	if len(account) != 32 {
		t.Error("account ID length")
	}
	if data, _ := os.ReadFile(manifest); bytes.Contains(data, value) {
		t.Error("manifest contains value")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(manifest)
		if info.Mode().Perm() != 0600 {
			t.Error("manifest mode")
		}
	} else {
		t.Log("Windows file ACLs do not expose Unix permission bits")
	}
	if err := Stash(dir, "keychain:demo", "TOKEN", map[string]string{"env": "dev"}, []byte("synthetic-new"), s); err != nil {
		t.Fatal(err)
	}
	records, err = ListNames(dir, "keychain:demo")
	if err != nil || len(records) != 1 || records[0].Account != account {
		t.Error("identity account not reused")
	}
	log, _ := os.ReadFile(filepath.Join(s.dir, "log"))
	if bytes.Contains(log, value) {
		t.Error("stub log contains value")
	}
	count := len(log)
	if _, err := ListNames(dir, "keychain:demo"); err != nil {
		t.Fatal(err)
	}
	log, _ = os.ReadFile(filepath.Join(s.dir, "log"))
	if len(log) != count {
		t.Error("list contacted provider")
	}
	if err := Stash(dir, "keychain:demo", "OTHER", nil, []byte("synthetic-other"), &stub{dir: s.dir, putFail: true}); err == nil {
		t.Error("put failure accepted")
	}
	records, _ = store.ReadManifest(manifest, "keychain")
	if len(records) != 1 {
		t.Error("put failure published")
	}
	if err := Stash(dir, "keychain:demo", "OTHER", nil, []byte("synthetic-other"), &stub{dir: s.dir, getFail: true}); err == nil {
		t.Error("verification failure accepted")
	}
	records, _ = store.ReadManifest(manifest, "keychain")
	if len(records) != 1 {
		t.Error("verification failure published")
	}
	// Inventory mapping: manifest_failure, orphan_exists, failed_publish_existing,
	// new_record_unpublished, prior_record_intact.
	publishFailure := func(string, string, string, map[string]string, string) error {
		return errors.New("synthetic publish failure")
	}
	if err := stashWithPublish(dir, "keychain:demo", "ORPHAN", nil, []byte("synthetic-orphan"), s, publishFailure); err == nil {
		t.Error("publish failure accepted")
	}
	records, err = store.ReadManifest(manifest, "keychain")
	if err != nil || len(records) != 1 {
		t.Error("publish failure changed inventory")
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "keychain", "secret", "demo"))
	if err != nil || len(entries) < 2 {
		t.Error("publish failure did not leave an orphan")
	}
	// A malformed manifest blocks a put and leaves the old inventory intact.
	if err := os.WriteFile(manifest, []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Stash(dir, "keychain:demo", "OTHER", nil, []byte("synthetic-other"), s); err == nil {
		t.Error("malformed manifest accepted")
	}
	if _, err := ListNames(dir, "libsecret:demo"); err == nil {
		t.Error("backend mismatch accepted")
	}
}

type labelStub struct {
	*stub
	label string
}

func (s *labelStub) Put(service, account, label string, value []byte) error {
	s.label = label
	return s.stub.Put(service, account, label, value)
}

func TestBackendDisplayLabels(t *testing.T) {
	for _, tc := range []struct {
		ref, want string
		labels    map[string]string
	}{
		{"keychain:demo", "secret/demo/TOKEN", nil},
		{"keychain:demo", "secret/demo/TOKEN/env=dev,zone=west", map[string]string{"zone": "west", "env": "dev"}},
		{"libsecret:demo", "secret demo TOKEN", nil},
		{"libsecret:demo", "secret demo TOKEN [env=dev,zone=west]", map[string]string{"zone": "west", "env": "dev"}},
	} {
		t.Run(tc.ref+"/"+tc.want, func(t *testing.T) {
			dir := t.TempDir()
			s := &labelStub{stub: &stub{dir: filepath.Join(dir, "stub")}}
			if err := Stash(dir, tc.ref, "TOKEN", tc.labels, []byte("synthetic"), s); err != nil {
				t.Fatal(err)
			}
			if s.label != tc.want {
				t.Errorf("label = %q, want %q", s.label, tc.want)
			}
		})
	}
}

type tooLargeStub struct{ *stub }

func (s *tooLargeStub) Put(string, string, string, []byte) error { return ErrValueTooLarge }

// The keychain size limit reaches the user like Bash's message, not as a generic failure.
func TestStashKeepsSizeLimitMessage(t *testing.T) {
	dir := t.TempDir()
	s := &tooLargeStub{stub: &stub{dir: filepath.Join(dir, "stub")}}
	err := Stash(dir, "keychain:demo", "TOKEN", nil, []byte("synthetic"), s)
	if !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("err = %v, want size limit", err)
	}
}

func TestConcurrentBackendSameIdentity(t *testing.T) {
	dir := t.TempDir()
	s := &stub{dir: filepath.Join(dir, "stub"), backend: "libsecret"}
	const count = 16
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Stash(dir, "libsecret:demo", "TOKEN", map[string]string{"env": "dev", "zone": "west"}, []byte("synthetic"), s)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	records, err := ListNames(dir, "libsecret:demo")
	if err != nil || len(records) != 1 {
		t.Fatalf("records = %d, %v", len(records), err)
	}
	entries, err := os.ReadDir(s.path("secret/demo", ""))
	if err != nil || len(entries) != 1 || entries[0].Name() != records[0].Account {
		t.Fatalf("accounts = %v, %v", entries, err)
	}
}

func TestRunProviderInheritedPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell process inheritance required")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "provider")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 10 &\nprintf synthetic\n"), 0700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, stderr, err := runProvider(script, nil, nil)
	if err == nil || len(out) != 0 || len(stderr) != 0 || time.Since(start) > 3*time.Second {
		t.Fatalf("inherited pipe: out %q stderr %q err %v elapsed %s", out, stderr, err, time.Since(start))
	}
}

func TestRunProviderOutputLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix shell provider required")
	}
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			script := filepath.Join(t.TempDir(), "provider")
			redirect := ""
			if stream == "stderr" {
				redirect = "1>&2"
			}
			if err := os.WriteFile(script, []byte("#!/bin/sh\nhead -c 2097152 /dev/zero "+redirect+"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			out, stderr, err := runProvider(script, nil, nil)
			if err == nil || len(out) != 0 || len(stderr) != 0 || time.Since(start) > 4*time.Second {
				t.Fatalf("output limit: out %d stderr %d err %v elapsed %s", len(out), len(stderr), err, time.Since(start))
			}
		})
	}
}
