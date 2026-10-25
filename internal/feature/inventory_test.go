package feature

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func syntheticMetadata(data []byte) store.Metadata {
	records, _ := store.ParseMetadata(data)
	return store.Metadata{Version: store.MetadataVersion, Reference: "file:/synthetic/team.secret", Backend: "file", Records: records}
}

func TestInventoryJSONGolden(t *testing.T) {
	metadata := syntheticMetadata([]byte("TOKEN=synthetic-first\nTOKEN=synthetic-last\nEMPTY=\n[env=prod]\nTOKEN=synthetic-prod\nONLY_PROD=synthetic-only\n[env=dev]\nDEV=synthetic-dev\n"))
	inventory, err := BuildInventory([]store.Metadata{metadata}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := BuildInventory([]store.Metadata{metadata}, store.Selectors{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	diff, err := DiffMetadata(metadata, metadata, store.Selectors{"env": "prod"}, store.Selectors{"env": "dev"})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := BuildInventory(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := BuildInventory([]store.Metadata{{
		Version: store.MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret",
		Records: []store.MetadataRecord{{Key: "TOKEN", Labels: map[string]string{"env": "prod"}, Account: "0123456789abcdef0123456789abcdef"}},
	}, syntheticMetadata(nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	document := struct {
		Inventory Inventory    `json:"inventory"`
		Selected  Inventory    `json:"selected"`
		Diff      MetadataDiff `json:"diff"`
		Empty     Inventory    `json:"empty"`
		Provider  Inventory    `json:"provider"`
	}{inventory, selected, diff, empty, provider}
	got, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "feature", "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Fatalf("inventory schema differs from names-only golden:\n%s", got)
	}
}

func TestMetadataSelectionParity(t *testing.T) {
	for _, tt := range []struct {
		name      string
		data      []byte
		selectors store.Selectors
		ambiguous bool
	}{
		{"flat duplicate", []byte("A=first\nB=second\nA=last\n"), nil, false},
		{"unlabeled only", []byte("A=base\n[env=prod]\nA=prod\nB=prod\n"), nil, false},
		{"subset and specificity", []byte("A=base\n[env=prod]\nA=prod\n[env=prod,region=west]\nA=west\n"), store.Selectors{"env": "prod", "region": "west"}, false},
		{"unmatched", []byte("[env=prod]\nA=prod\n"), store.Selectors{"env": "dev"}, false},
		{"same identity last wins", []byte("[env=prod]\nA=first\nA=last\n"), store.Selectors{"env": "prod"}, false},
		{"distinct tied labels", []byte("[env=prod]\nA=prod\n[region=west]\nA=west\n"), store.Selectors{"env": "prod", "region": "west"}, true},
		{"duplicate cannot resolve tie", []byte("[env=prod]\nA=prod\n[region=west]\nA=west\nA=again\n"), store.Selectors{"env": "prod", "region": "west"}, true},
		{"higher specificity resolves tie", []byte("[env=prod]\nA=prod\n[region=west]\nA=west\n[env=prod,region=west]\nA=both\n"), store.Selectors{"env": "prod", "region": "west"}, false},
		{"later lower specificity cannot replace", []byte("[env=prod,region=west]\nA=both\n[env=prod]\nA=prod\n[region=west]\nA=west\n"), store.Selectors{"env": "prod", "region": "west"}, false},
		{"malformed and reset", []byte("[env=prod]\nA='unterminated\n[bad header]\nB=prod\n[]\nC=base\n"), nil, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records, _ := store.Parse(tt.data)
			defer func() {
				for _, record := range records {
					secure.Clear(record.Value)
				}
			}()
			legacy, legacyErr := store.Select(records, tt.selectors)
			metadata := syntheticMetadata(tt.data)
			got, err := SelectMetadata(metadata, tt.selectors)
			if tt.ambiguous {
				if !errors.Is(err, ErrMetadataAmbiguous) || legacyErr == nil {
					t.Fatalf("ambiguity: metadata %v, legacy %v", err, legacyErr)
				}
				if _, err := DiffMetadata(metadata, metadata, tt.selectors, nil); !errors.Is(err, ErrMetadataAmbiguous) {
					t.Fatal("diff accepted ambiguous labels")
				}
				if _, err := BuildInventory([]store.Metadata{metadata}, tt.selectors); !errors.Is(err, ErrMetadataAmbiguous) {
					t.Fatal("inventory accepted ambiguous labels")
				}
				return
			}
			if err != nil || legacyErr != nil {
				t.Fatalf("selection: metadata %v, legacy %v", err, legacyErr)
			}
			if !reflect.DeepEqual(got.Keys, legacy.Keys) || len(got.Matched) != len(legacy.Matched) {
				t.Fatal("metadata and value selection names differ")
			}
			for key, want := range legacy.Matched {
				r, ok := got.Matched[key]
				if !ok || r.Line != want.Line || !reflect.DeepEqual(r.Labels, want.Labels) {
					t.Fatalf("selection differs for %s", key)
				}
			}
		})
	}
}

func TestInventoryValueIndependence(t *testing.T) {
	left := syntheticMetadata([]byte("TOKEN=synthetic-one\nTOKEN=\"synthetic-two\"\n[env=prod]\nTOKEN=small\nEMPTY=\n"))
	right := syntheticMetadata([]byte("TOKEN=\nTOKEN=changed-to-a-much-longer-synthetic-value\n[env=prod]\nTOKEN=\xff\xfe\nEMPTY=synthetic-was-empty\n"))
	for _, selectors := range []store.Selectors{nil, {"env": "prod"}, {"env": "dev"}} {
		a, err := BuildInventory([]store.Metadata{left}, selectors)
		if err != nil {
			t.Fatal(err)
		}
		b, err := BuildInventory([]store.Metadata{right}, selectors)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatal("changing only values changed inventory")
		}
		before, err := DiffMetadata(left, left, nil, selectors)
		if err != nil {
			t.Fatal(err)
		}
		after, err := DiffMetadata(left, right, nil, selectors)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("changing only values changed diff")
		}
		encoded, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("synthetic-was-empty")) || bytes.Contains(encoded, []byte("synthetic-value")) {
			t.Fatal("value sentinel in inventory")
		}
		for _, forbidden := range []string{"value", "length", "digest", "hash", "equal", "line", "labeled_store"} {
			if bytes.Contains(encoded, []byte(`"`+forbidden+`"`)) {
				t.Fatalf("forbidden metadata field %s", forbidden)
			}
		}
	}
}

func TestReadMetadataAndNoProviderCalls(t *testing.T) {
	dir := testutil.TempDir(t)
	// External providers are spies only. Any invocation, including Get, is a failure.
	if runtime.GOOS != "windows" {
		marker := filepath.Join(dir, "provider-called")
		tools := filepath.Join(dir, "tools")
		if err := testutil.Mkdir(tools, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"security", "secret-tool"} {
			if err := testutil.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\nprintf called > \"$SYNTH_METADATA_PROVIDER_MARKER\"\nexit 1\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("PATH", tools)
		t.Setenv("SYNTH_METADATA_PROVIDER_MARKER", marker)
		t.Cleanup(func() {
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Error("names-only workflow invoked a provider")
			}
		})
	}
	// Invalid ambient configuration must not block metadata-only keychain access.
	t.Setenv("SECRET_KEYCHAIN", "not-an-absolute-keychain-path")
	for _, backend := range []string{"keychain", "libsecret"} {
		t.Run(backend, func(t *testing.T) {
			manifest := []byte("secret-manifest-v1\nbackend=" + backend + "\nTOKEN\t\t0123456789abcdef0123456789abcdef\nTOKEN\tenv=prod\tfedcba9876543210fedcba9876543210\n")
			if err := testutil.WriteFile(filepath.Join(dir, "synthetic.keys"), manifest, 0600); err != nil {
				t.Fatal(err)
			}
			ref := backend + ":synthetic"
			metadata, err := ReadMetadata(ref, dir)
			if err != nil {
				t.Fatal(err)
			}
			if metadata.Backend != backend || len(metadata.Records) != 2 || metadata.Records[0].Account != "0123456789abcdef0123456789abcdef" {
				t.Fatal("incorrect provider metadata")
			}
			if _, err = LoadInventory([]string{ref}, dir, nil); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadInventory([]string{ref}, dir, store.Selectors{"env": "prod"}); err != nil {
				t.Fatal(err)
			}
			if _, err = DiffMetadata(metadata, metadata, nil, store.Selectors{"env": "prod"}); err != nil {
				t.Fatal(err)
			}
		})
	}
	path := filepath.Join(dir, "synthetic.secret")
	if err := testutil.WriteFile(path, []byte("TOKEN=synthetic-secret-not-metadata\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{path, "file:" + path} {
		metadata, err := ReadMetadata(ref, dir)
		if err != nil || len(metadata.Records) != 1 || metadata.Backend != "file" || metadata.Reference != ref {
			t.Fatalf("file metadata failed: %v", err)
		}
	}
}

func TestMetadataReadFailures(t *testing.T) {
	dir := testutil.TempDir(t)
	if err := testutil.WriteFile(filepath.Join(dir, "synthetic.keys"), []byte("secret-manifest-v1\nbackend=libsecret\nTOKEN\t\tsynthetic-provider-output-sentinel\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"", "file:", "keychain:../escape", "libsecret:bad/name", "libsecret:synthetic", "keychain:missing", "file:" + dir, "file:" + filepath.Join(dir, "missing")} {
		if _, err := ReadMetadata(ref, dir); err == nil {
			t.Errorf("accepted invalid metadata source %q", ref)
		} else if !errors.Is(err, ErrMetadata) && !errors.Is(err, ErrMetadataRead) {
			t.Errorf("nonfixed metadata error: %v", err)
		}
	}
	if _, err := ReadMetadata("keychain:synthetic", ""); !errors.Is(err, ErrMetadata) {
		t.Fatal("accepted implicit manifest directory")
	}
	if _, err := LoadInventory([]string{"libsecret:synthetic"}, dir, nil); !errors.Is(err, ErrMetadataRead) {
		t.Fatal("load hid malformed manifest")
	}
}

func TestMetadataOwnershipAndValidation(t *testing.T) {
	metadata := syntheticMetadata([]byte("[env=prod]\nTOKEN=synthetic\n"))
	selectors := store.Selectors{"env": "prod"}
	inventory, err := BuildInventory([]store.Metadata{metadata}, selectors)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := SelectMetadata(metadata, selectors)
	if err != nil {
		t.Fatal(err)
	}
	diff, err := DiffMetadata(metadata, metadata, selectors, selectors)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Records[0].Labels["env"] = "changed"
	selectors["env"] = "changed"
	if inventory.Stores[0].Records[0].Labels["env"] != "prod" || selection.Matched["TOKEN"].Labels["env"] != "prod" || diff.Left.Selectors["env"] != "prod" || diff.Records[0].Right.Labels["env"] != "prod" {
		t.Fatal("metadata result aliases borrowed labels")
	}
	diff.Records[0].Left.Labels["env"] = "another"
	if diff.Records[0].Right.Labels["env"] != "prod" {
		t.Fatal("diff sides alias labels")
	}
	valid := syntheticMetadata([]byte("TOKEN=synthetic\n"))
	for _, selectors := range []store.Selectors{{"invalid-name": "value"}, {"env": "bad value"}} {
		if _, err := SelectMetadata(valid, selectors); !errors.Is(err, store.ErrInvalidSelector) {
			t.Fatal("invalid selector accepted")
		}
		if _, err := BuildInventory(nil, selectors); !errors.Is(err, store.ErrInvalidSelector) {
			t.Fatal("empty inventory ignored invalid selector")
		}
		if _, err := LoadInventory([]string{"file:" + filepath.Join(testutil.TempDir(t), "missing")}, "", selectors); !errors.Is(err, store.ErrInvalidSelector) {
			t.Fatal("load accessed store before rejecting invalid selector")
		}
	}
	for _, mutate := range []func(*store.Metadata){
		func(m *store.Metadata) { m.Version = 999 },
		func(m *store.Metadata) { m.Backend = "unknown" },
		func(m *store.Metadata) { m.Reference = "" },
		func(m *store.Metadata) { m.Backend = "libsecret" },
		func(m *store.Metadata) { m.Backend, m.Reference = "libsecret", "libsecret" },
		func(m *store.Metadata) { m.Backend, m.Reference = "libsecret", "libsecret:../escape" },
		func(m *store.Metadata) { m.Records[0].Account = "synthetic-not-an-account" },
		func(m *store.Metadata) {
			m.Backend, m.Reference = "libsecret", "libsecret:synthetic"
			m.Records[0].Account = "synthetic-not-an-account"
		},
		func(m *store.Metadata) { m.Records[0].Key = "bad-key" },
		func(m *store.Metadata) { m.Records[0].Labels["env"] = "bad value" },
	} {
		metadata := syntheticMetadata([]byte("TOKEN=synthetic\n"))
		mutate(&metadata)
		if _, err := BuildInventory([]store.Metadata{metadata}, nil); !errors.Is(err, ErrMetadata) {
			t.Fatal("accepted invalid metadata")
		}
	}
}

func TestDiffMetadataCrossStore(t *testing.T) {
	left := syntheticMetadata([]byte("A=synthetic\nB=synthetic\n"))
	right := store.Metadata{Version: store.MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret", Records: []store.MetadataRecord{
		{Key: "B", Labels: map[string]string{"env": "prod"}, Account: "0123456789abcdef0123456789abcdef"},
		{Key: "C", Account: "fedcba9876543210fedcba9876543210"},
	}}
	diff, err := DiffMetadata(left, right, nil, store.Selectors{"env": "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if diff.Left.Backend != "file" || diff.Right.Backend != "libsecret" || len(diff.Records) != 3 || diff.Records[0].Key != "A" || diff.Records[1].Key != "B" || diff.Records[2].Key != "C" {
		t.Fatal("diff lost backend or left-first key order")
	}
	if !diff.Records[0].Left.Present || diff.Records[0].Right.Present || diff.Records[2].Left.Present || !diff.Records[2].Right.Present {
		t.Fatal("incorrect cross-store presence")
	}
	encoded, err := json.Marshal(diff)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "0123456789abcdef") || strings.Contains(string(encoded), "account") {
		t.Fatal("diff reports account changes")
	}
	left.Records[0].Line = 999
	right.Records[0].Account = "11111111111111111111111111111111"
	after, err := DiffMetadata(left, right, nil, store.Selectors{"env": "prod"})
	if err != nil || !reflect.DeepEqual(diff, after) {
		t.Fatal("diff changed after source line or provider account change")
	}
}

func FuzzMetadataSelection(f *testing.F) {
	f.Add([]byte("TOKEN=synthetic\n[env=prod]\nTOKEN=synthetic-prod\n"))
	f.Add([]byte("[env=prod]\nTOKEN=a\n[region=west]\nTOKEN=b\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		metadata := syntheticMetadata(data)
		records, _ := store.Parse(data)
		defer func() {
			for _, record := range records {
				secure.Clear(record.Value)
			}
		}()
		selectors := store.Selectors{"env": "prod", "region": "west"}
		got, err := SelectMetadata(metadata, selectors)
		want, wantErr := store.Select(records, selectors)
		if (err != nil) != (wantErr != nil) {
			t.Fatal("metadata and value selection disagree on ambiguity")
		}
		if err == nil {
			// Nil and empty key slices are equivalent for an empty store.
			if len(got.Keys) != len(want.Keys) || len(got.Matched) != len(want.Matched) {
				t.Fatal("metadata and value selection names differ")
			}
			for i, key := range got.Keys {
				if key != want.Keys[i] {
					t.Fatal("metadata and value selection order differs")
				}
			}
			for key, record := range got.Matched {
				other := want.Matched[key]
				if record.Line != other.Line || !reflect.DeepEqual(record.Labels, other.Labels) {
					t.Fatal("metadata and value selection identity differs")
				}
			}
		}
	})
}
