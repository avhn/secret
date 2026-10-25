package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/avhn/secret/internal/secure"
)

func v2Record() ManifestV2Record {
	return ManifestV2Record{Key: "API_KEY", Labels: map[string]string{}, ID: strings.Repeat("a", 32), Provider: OnePasswordReference{Reference: "op://" + strings.Repeat("v", 26) + "/" + strings.Repeat("i", 26) + "/password", AccountUUID: strings.Repeat("a", 26), Auth: "service-account"}}
}
func TestManifestV2Contract(t *testing.T) {
	r := v2Record()
	data, err := EncodeManifestV2([]ManifestV2Record{r}, "onepassword")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseManifestV2(data, "onepassword")
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	again, _ := EncodeManifestV2(got, "onepassword")
	if !bytes.Equal(data, again) {
		t.Fatal("unstable encoding")
	}
	if ProjectManifestV2(got)[0].Account != r.ID {
		t.Fatal("provider account exposed")
	}
	cases := map[string][]byte{
		"version":          bytes.Replace(data, []byte("v2"), []byte("v1"), 1),
		"backend":          bytes.Replace(data, []byte("backend=onepassword"), []byte("backend=age"), 1),
		"unknown":          bytes.Replace(data, []byte(`"key":`), []byte(`"extra":0,"key":`), 1),
		"duplicate":        bytes.Replace(data, []byte(`"key":`), []byte(`"key":"OTHER","key":`), 1),
		"nested duplicate": bytes.Replace(data, []byte(`"auth":`), []byte(`"auth":"session","auth":`), 1),
		"missing labels":   bytes.Replace(data, []byte(`"labels":{},`), nil, 1),
		"null labels":      bytes.Replace(data, []byte(`"labels":{}`), []byte(`"labels":null`), 1),
		"missing LF":       data[:len(data)-1], "extra JSON": append(append([]byte{}, data[:len(data)-1]...), []byte(" {}\n")...),
		"oversize": bytes.Repeat([]byte{'x'}, ManifestV2Limit+1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifestV2(input, "onepassword"); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	for _, change := range []func(*ManifestV2Record){
		func(r *ManifestV2Record) { r.ID = "bad" }, func(r *ManifestV2Record) { r.Provider.Auth = "session" },
		func(r *ManifestV2Record) { r.Provider.Reference = "op://Vault/Item/password" },
		func(r *ManifestV2Record) { r.Provider.Reference += "?query" }, func(r *ManifestV2Record) { r.Provider.Reference += "/%61" },
		func(r *ManifestV2Record) { r.Provider.Reference += "/.." }, func(r *ManifestV2Record) { r.Provider.Reference += "\n" },
	} {
		r := v2Record()
		change(&r)
		if _, err := EncodeManifestV2([]ManifestV2Record{r}, "onepassword"); err == nil {
			t.Fatal("accepted invalid record")
		}
	}
	for _, change := range []func(*ManifestV2Record){func(r *ManifestV2Record) { r.ID = strings.Repeat("b", 32) }, func(r *ManifestV2Record) { r.Key = "OTHER" }, func(r *ManifestV2Record) { r.Provider.AccountUUID = strings.Repeat("b", 26) }} {
		other := v2Record()
		change(&other)
		if _, err := EncodeManifestV2([]ManifestV2Record{v2Record(), other}, "onepassword"); err == nil {
			t.Fatal("accepted duplicate binding")
		}
	}
	records := make([]ManifestV2Record, ManifestV2Records+1)
	if _, err := EncodeManifestV2(records, "onepassword"); err == nil {
		t.Fatal("accepted oversized inventory")
	}
	if _, err := ParseManifest(data, "keychain"); err == nil {
		t.Fatal("v1 accepted v2")
	}
}
func TestManifestV2PrivateRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private Unix writer")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "test.onepassword-keys")
	r := v2Record()
	if err := RegisterManifestV2(path, r); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	if err := RegisterManifestV2(path, r); !errors.Is(err, secure.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(original, after) {
		t.Fatal("failure changed manifest")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("mode")
	}
	alias := filepath.Join(dir, "alias.onepassword-keys")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifestV2(alias, "onepassword"); err == nil {
		t.Fatal("followed alias")
	}
	if err := RegisterManifestV2(alias, r); err == nil {
		t.Fatal("replaced alias")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifestV2(path, "onepassword"); err == nil {
		t.Fatal("accepted public manifest")
	}
}
func TestManifestV2ConcurrentRegistration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private Unix writer")
	}
	path := filepath.Join(t.TempDir(), "test.onepassword-keys")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- RegisterManifestV2(path, v2Record()) }()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes: %d", successes)
	}
	records, err := ReadManifestV2(path, "onepassword")
	if err != nil || len(records) != 1 {
		t.Fatalf("inventory: %v", err)
	}
}

func TestManifestV2AtomicFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private Unix writer")
	}
	path := filepath.Join(t.TempDir(), "test.onepassword-keys")
	if err := RegisterManifestV2(path, v2Record()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	next := v2Record()
	next.Key = "OTHER"
	next.ID = strings.Repeat("b", 32)
	next.Provider.Reference = strings.TrimSuffix(next.Provider.Reference, "password") + "other"
	err := registerManifestV2(path, next, func(*os.Root, string, []byte) error { return errors.New("synthetic atomic failure") })
	if err != secure.ErrTransaction {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed publisher changed manifest")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("failed publisher left debris")
	}
}
func TestManifestV2LimitsAndBindings(t *testing.T) {
	r := v2Record()
	r.Labels["env"] = strings.Repeat("x", ManifestV2RecordLimit)
	if _, err := EncodeManifestV2([]ManifestV2Record{r}, "onepassword"); err == nil {
		t.Fatal("record size accepted")
	}
	first := v2Record()
	second := v2Record()
	second.Key = "OTHER"
	second.ID = strings.Repeat("b", 32)
	if _, err := EncodeManifestV2([]ManifestV2Record{first, second}, "onepassword"); err == nil {
		t.Fatal("duplicate reference accepted")
	}
	second.Provider.Reference = strings.TrimSuffix(second.Provider.Reference, "password") + "other"
	second.ID = first.ID
	if _, err := EncodeManifestV2([]ManifestV2Record{first, second}, "onepassword"); err == nil {
		t.Fatal("duplicate local ID accepted")
	}
	second.ID = strings.Repeat("b", 32)
	second.Provider.AccountUUID = strings.Repeat("b", 26)
	if _, err := EncodeManifestV2([]ManifestV2Record{first, second}, "onepassword"); err == nil {
		t.Fatal("mixed account accepted")
	}
	if _, err := EncodeManifestV2(nil, "future"); err == nil {
		t.Fatal("future schema accepted")
	}
}
func FuzzManifestV2(f *testing.F) {
	data, _ := EncodeManifestV2([]ManifestV2Record{v2Record()}, "onepassword")
	f.Add(data)
	f.Add([]byte(manifestV2Header))
	f.Fuzz(func(t *testing.T, data []byte) {
		records, err := ParseManifestV2(data, "onepassword")
		if err != nil {
			return
		}
		encoded, err := EncodeManifestV2(records, "onepassword")
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatal("accepted noncanonical container")
		}
	})
}
