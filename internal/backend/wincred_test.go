package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

type fakeWincredAPI struct {
	readCall   func(string) (*wincredRecord, error)
	writeCall  func(string, []byte) error
	deleteCall func(string) error
}

func (f fakeWincredAPI) read(target string) (*wincredRecord, error) { return f.readCall(target) }
func (f fakeWincredAPI) write(target string, blob []byte) error     { return f.writeCall(target, blob) }
func (f fakeWincredAPI) delete(target string) error                 { return f.deleteCall(target) }

const wincredTestAccount = "0123456789abcdef0123456789abcdef"
const wincredTestService = "secret/synthetic"
const wincredTestTarget = wincredTestService + "/" + wincredTestAccount
const wincredTestLabel = "secret/synthetic/TOKEN"

func TestWincredReadOwnership(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		kind                   uint32
		target                 string
		size                   int
		nilRecord, fail, valid bool
	}{
		{"raw", wincredGeneric, wincredTestTarget, 5, false, false, true},
		{"empty", wincredGeneric, wincredTestTarget, 0, false, false, true},
		{"maximum", wincredGeneric, wincredTestTarget, wincredBlobLimit, false, false, true},
		{"oversize", wincredGeneric, wincredTestTarget, wincredBlobLimit + 1, false, false, false},
		{"type", 2, wincredTestTarget, 5, false, false, false},
		{"adjacent", wincredGeneric, wincredTestTarget + "0", 5, false, false, false},
		{"missing target", wincredGeneric, "", 5, false, false, false},
		{"api failure", wincredGeneric, wincredTestTarget, 5, false, true, false},
		{"nil", 0, "", 0, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blob := bytes.Repeat([]byte{0xff, 0, '\n', '\r', 'x'}, (tc.size+4)/5)[:tc.size]
			want := bytes.Clone(blob)
			released := false
			api := fakeWincredAPI{readCall: func(target string) (*wincredRecord, error) {
				if target != wincredTestTarget {
					t.Fatal("inexact read target")
				}
				if tc.nilRecord {
					return nil, nil
				}
				record := &wincredRecord{kind: tc.kind, target: tc.target, blob: blob, size: uint32(tc.size), release: func() {
					if !bytes.Equal(blob, make([]byte, len(blob))) {
						t.Error("API allocation freed before clearing")
					}
					released = true
				}}
				if tc.fail {
					return record, errors.New("synthetic-provider-value")
				}
				return record, nil
			}}
			got, err := (wincred{api: api}).Get(wincredTestService, wincredTestAccount)
			defer secure.Clear(got)
			if (err == nil) != tc.valid {
				t.Fatal("incorrect read result")
			}
			if !tc.nilRecord && !released {
				t.Fatal("API allocation retained")
			}
			if tc.valid && !bytes.Equal(got, want) {
				t.Fatal("raw owned bytes changed")
			}
			if err != nil && (err.Error() != "backend lookup failed" || got != nil) {
				t.Fatal("nonfixed lookup failure")
			}
		})
	}
	for _, size := range []uint32{1, wincredBlobLimit + 1} {
		api := fakeWincredAPI{readCall: func(string) (*wincredRecord, error) {
			return &wincredRecord{kind: wincredGeneric, target: wincredTestTarget, size: size}, nil
		}}
		if _, err := (wincred{api: api}).Get(wincredTestService, wincredTestAccount); err == nil {
			t.Fatal("inconsistent blob size accepted")
		}
	}
}

func TestWincredWriteOwnership(t *testing.T) {
	for _, size := range []int{0, 5, wincredBlobLimit, wincredBlobLimit + 1} {
		for _, fail := range []bool{false, true} {
			value := bytes.Repeat([]byte{0xff}, size)
			var borrowed []byte
			called := false
			api := fakeWincredAPI{writeCall: func(target string, blob []byte) error {
				called, borrowed = true, blob
				if target != wincredTestTarget || !bytes.Equal(blob, value) {
					t.Fatal("write target or raw bytes changed")
				}
				if fail {
					return errors.New("synthetic-provider-value")
				}
				return nil
			}}
			err := (wincred{api: api}).Put(wincredTestService, wincredTestAccount, wincredTestLabel, value)
			if called != (size <= wincredBlobLimit) || (err == nil) != (size <= wincredBlobLimit && !fail) {
				t.Fatal("incorrect put result")
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("write buffer not cleared")
			}
			if !bytes.Equal(value, bytes.Repeat([]byte{0xff}, size)) {
				t.Fatal("caller buffer modified")
			}
			if err != nil && err.Error() != "backend put failed" {
				t.Fatal("nonfixed put failure")
			}
		}
	}
}

func TestWincredExactDeleteAndValidation(t *testing.T) {
	for _, tc := range []struct{ service, account string }{
		{"secret/../other", wincredTestAccount}, {"secret/a/b", wincredTestAccount},
		{"secret/synthetic", strings.ToUpper(wincredTestAccount)}, {wincredTestService, "short"},
		{"secret/" + strings.Repeat("a", wincredTargetLimit), wincredTestAccount},
	} {
		p := wincred{api: fakeWincredAPI{}}
		if _, err := p.Get(tc.service, tc.account); err == nil {
			t.Fatal("invalid get reached API")
		}
		if p.Put(tc.service, tc.account, wincredTestLabel, []byte("synthetic")) == nil {
			t.Fatal("invalid put reached API")
		}
		if p.Delete(tc.service, tc.account) == nil {
			t.Fatal("invalid delete reached API")
		}
	}
	for _, fail := range []bool{false, true} {
		p := wincred{api: fakeWincredAPI{deleteCall: func(target string) error {
			if target != wincredTestTarget {
				t.Fatal("inexact delete target")
			}
			if fail {
				return errors.New("synthetic-provider-value")
			}
			return nil
		}}}
		err := p.Delete(wincredTestService, wincredTestAccount)
		if (err != nil) != fail || (err != nil && err.Error() != "backend delete failed") {
			t.Fatal("nonfixed delete result")
		}
	}
	if (wincred{api: fakeWincredAPI{}}).Put(wincredTestService, wincredTestAccount, "bad\x00label", nil) == nil {
		t.Fatal("invalid label reached API")
	}
}

func TestWincredStashFailurePublication(t *testing.T) {
	for _, phase := range []string{"put", "read", "mismatch", "publish"} {
		t.Run(phase, func(t *testing.T) {
			dir := testutil.TempDir(t)
			path, _ := store.ManifestPath(dir, "wincred:synthetic")
			var borrowed []byte
			api := fakeWincredAPI{
				writeCall: func(string, []byte) error {
					if phase == "put" {
						return errors.New("synthetic-provider-value")
					}
					return nil
				},
				readCall: func(target string) (*wincredRecord, error) {
					borrowed = []byte("synthetic-value")
					if phase == "mismatch" {
						borrowed[0] = 'x'
					}
					record := &wincredRecord{kind: wincredGeneric, target: target, blob: borrowed, size: uint32(len(borrowed))}
					if phase == "read" {
						return record, errors.New("synthetic-provider-value")
					}
					return record, nil
				},
			}
			err := stashWithPublish(dir, "wincred:synthetic", "TOKEN", nil, []byte("synthetic-value"), wincred{api: api}, func(string, string, string, map[string]string, string) error {
				if phase != "publish" {
					t.Fatal("failed verification reached publication")
				}
				return errors.New("synthetic-provider-value")
			})
			if err == nil || strings.Contains(err.Error(), "synthetic") {
				t.Fatal("nonfixed stash failure")
			}
			if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("failed stash retained API read buffer")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("failed stash published an inventory")
			}
		})
	}
}

func TestWincredTargetBoundary(t *testing.T) {
	service := "secret/" + strings.Repeat("a", wincredTargetLimit-len("secret/")-1-len(wincredTestAccount))
	if target, ok := wincredTarget(service, wincredTestAccount); !ok || len(target) != wincredTargetLimit {
		t.Fatal("maximum generic target rejected")
	}
	if _, ok := wincredTarget(service+"a", wincredTestAccount); ok {
		t.Fatal("oversized generic target accepted")
	}
}

func TestWincredManifestDispatch(t *testing.T) {
	dir := testutil.TempDir(t)
	path, _ := store.ManifestPath(dir, "wincred:synthetic")
	// A similarly named legacy inventory must never be consulted or overwritten.
	legacy := filepath.Join(dir, "synthetic.keys")
	if err := testutil.WriteFile(legacy, []byte("unrelated synthetic file"), 0600); err != nil {
		t.Fatal(err)
	}
	values := make(map[string][]byte)
	api := fakeWincredAPI{
		writeCall: func(target string, blob []byte) error { values[target] = bytes.Clone(blob); return nil },
		deleteCall: func(target string) error {
			if _, ok := values[target]; !ok {
				return errWincredMissing
			}
			delete(values, target)
			return nil
		},
		readCall: func(target string) (*wincredRecord, error) {
			blob, ok := values[target]
			if !ok {
				return nil, errWincredMissing
			}
			return &wincredRecord{kind: wincredGeneric, target: target, blob: bytes.Clone(blob), size: uint32(len(blob))}, nil
		},
	}
	p := wincred{api: api}
	selected, kind, service, err := DispatchWith("wincred:synthetic", p)
	if err != nil || selected == nil || kind != "wincred" || service != wincredTestService {
		t.Fatal("wincred dispatch failed")
	}
	if err := Stash(dir, "wincred:synthetic", "TOKEN", map[string]string{"env": "test"}, []byte("synthetic-value"), p); err != nil {
		t.Fatal(err)
	}
	records, err := ListNames(dir, "wincred:synthetic")
	if err != nil || len(records) != 1 || records[0].Key != "TOKEN" {
		t.Fatal("names-only dispatch failed")
	}
	data, err := os.ReadFile(path)
	if err != nil || bytes.Contains(data, []byte("synthetic-value")) {
		t.Fatal("value entered manifest")
	}
	data, err = os.ReadFile(legacy)
	if err != nil || string(data) != "unrelated synthetic file" {
		t.Fatal("legacy inventory changed")
	}
	if runtime.GOOS != "windows" {
		if _, _, _, err := Dispatch("wincred:synthetic"); !errors.Is(err, ErrUnsupported) {
			t.Fatal("non-Windows provider not unsupported")
		}
	}
	if runtime.GOOS == "windows" {
		// Step 6 lifted the Windows operator guard with native transaction tests;
		// rotating the stashed identity through the injected API must keep one
		// names-only record.
		if err := (Transaction{SecretsDir: dir, Reference: "wincred:synthetic", Provider: p}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Labels: map[string]string{"env": "test"}, Value: []byte("synthetic")}}); err != nil {
			t.Fatal("Windows operator transaction failed")
		}
		records, err := ListNames(dir, "wincred:synthetic")
		if err != nil || len(records) != 1 || records[0].Key != "TOKEN" {
			t.Fatal("transaction inventory changed shape")
		}
		if data, err := os.ReadFile(path); err != nil || bytes.Contains(data, []byte("synthetic-value")) {
			t.Fatal("value entered manifest")
		}
	}
}
