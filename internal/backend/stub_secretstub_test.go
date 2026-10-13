//go:build secretstub

package backend

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTaggedStubFailureInjection(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SECRET_BACKEND_STUB_DIR", dir)
	provider, _, service, err := Dispatch("keychain:demo")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provider.(directoryStub); !ok {
		t.Fatal("tagged dispatch did not select directory provider")
	}
	account := "0123456789abcdef0123456789abcdef"
	if err := provider.Put(service, account, "synthetic", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	got, err := provider.Get(service, account)
	if err != nil || !bytes.Equal(got, []byte("synthetic")) {
		t.Fatal("tagged provider roundtrip failed")
	}
	t.Setenv("SECRET_BACKEND_STUB_GET_FAIL", "1")
	if _, err := provider.Get(service, account); err == nil {
		t.Fatal("get failure injection ignored")
	}
	t.Setenv("SECRET_BACKEND_STUB_GET_FAIL", "")
	if err := os.WriteFile(filepath.Join(dir, "keychain", service, account), []byte("bad\nvalue"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Get(service, account); err == nil {
		t.Fatal("invalid provider bytes accepted")
	}
	t.Setenv("SECRET_BACKEND_STUB_MANIFEST_FAIL", "1")
	if err := stubPublishFailure(provider); err == nil {
		t.Fatal("publish failure injection ignored")
	}
}
