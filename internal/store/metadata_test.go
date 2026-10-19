package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func checkMetadataParity(t *testing.T, data []byte) {
	t.Helper()
	records, warnings := Parse(data)
	metadata, metadataWarnings := ParseMetadata(data)
	if !reflect.DeepEqual(warnings, metadataWarnings) || len(records) != len(metadata) {
		t.Fatal("metadata grammar or warning parity changed")
	}
	withoutValues, _ := parse(data, false)
	for i, record := range records {
		if withoutValues[i].Value != nil {
			t.Fatal("metadata parser retained value bytes")
		}
		want := MetadataRecord{Key: record.Key, Labels: record.Labels, Line: record.Line, LabeledStore: record.LabeledStore}
		if !reflect.DeepEqual(metadata[i], want) {
			t.Fatalf("metadata mismatch at record %d", i)
		}
	}
}

func TestMetadataParserSemantics(t *testing.T) {
	for _, source := range []string{
		"",
		"# comment\nexport KEY='literal $ # = \\ text'\nKEY=last\nEMPTY=\n",
		"[zone=b,env=prod]\nKEY=first\n[env=prod]\nKEY=second\n[]\nKEY=default\n",
		"[env=prod]\nKEY=first\n[env=prod,env=qa]\nKEY=next\n[not a header]\nOTHER=value\n",
		"BAD='open\nNOT KEY=x\nBAD=x\x00y\nBAD=x\ry\nBAD=\"open\n",
		"KEY=\xffbinary\r\nOTHER=last",
		"KEY=trailing-cr\r",
		"KEY=first\nKEY=last\n[env=prod]\n[]\n",
	} {
		checkMetadataParity(t, []byte(source))
	}
}

func TestMetadataParserExistingFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "testdata", "store", "fixtures", "*.store"))
	if err != nil || len(paths) == 0 {
		t.Fatal("missing synthetic parser fixtures")
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			checkMetadataParity(t, data)
		})
	}
}

func TestMetadataOwnsNamesOnly(t *testing.T) {
	data := []byte("[env=prod]\nTOKEN=synthetic-value-sentinel\nTOKEN=other\n")
	records, warnings := ParseMetadata(data)
	clear(data)
	if len(records) != 2 || len(warnings) != 1 || records[0].Key != "TOKEN" || records[0].Labels["env"] != "prod" {
		t.Fatal("metadata borrowed cleared input")
	}
	records[0].Labels["env"] = "changed"
	if records[1].Labels["env"] != "prod" {
		t.Fatal("record labels share mutable ownership")
	}
	if strings.Contains(warnings[0].Text, "sentinel") {
		t.Fatal("warning exposed synthetic value")
	}
}

func TestMetadataIndependentOfValues(t *testing.T) {
	first, _ := ParseMetadata([]byte("[env=prod]\nTOKEN=synthetic-short\nTOKEN=\"another\"\n[]\nEMPTY=\n"))
	second, _ := ParseMetadata([]byte("[env=prod]\nTOKEN=much-longer-synthetic-value\nTOKEN='different'\n[]\nEMPTY=now-present\n"))
	a, err := json.Marshal(Metadata{Version: MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret", Records: first})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(Metadata{Version: MetadataVersion, Reference: "libsecret:synthetic", Backend: "libsecret", Records: second})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("changed value bytes affected metadata JSON")
	}
	for _, forbidden := range []string{"synthetic-short", "value", "length", "digest", "hash", "equal"} {
		if bytes.Contains(a, []byte(forbidden)) {
			t.Fatal("metadata JSON includes a value-bearing field")
		}
	}
}

func TestMetadataAndAuditTypesExcludeValueFields(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeFor[MetadataRecord](), reflect.TypeFor[Metadata](), reflect.TypeFor[AuditEvent]()} {
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{"value", "length", "digest", "hash", "argv", "stderr", "message", "error"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s has forbidden field %s", typ.Name(), field.Name)
				}
			}
		}
	}
	encoded, err := json.Marshal(Mutation{Kind: MutationPut, Key: "TOKEN", Value: []byte("synthetic-value")})
	if err != nil || bytes.Contains(encoded, []byte("Value")) || bytes.Contains(encoded, []byte("c3ludGhldGlj")) {
		t.Fatal("mutation value was serialized")
	}
}

func TestOperatorActions(t *testing.T) {
	for _, action := range []OperatorAction{ActionImport, ActionExport, ActionRotate, ActionRename, ActionDelete} {
		if !action.Valid() {
			t.Fatalf("valid operator %q rejected", action)
		}
	}
	for _, action := range []OperatorAction{"", "run", "get", "delete --yes", "migrate"} {
		if action.Valid() {
			t.Fatalf("unexpected operator %q accepted", action)
		}
	}
}

func FuzzMetadataParse(f *testing.F) {
	for _, data := range [][]byte{nil, []byte("KEY=synthetic\nKEY=other\n"), []byte("[env=prod]\nKEY='synthetic'\r\n[]\nKEY=\xff\n"), []byte("BAD='open\n[env=prod,env=qa]\nKEY=synthetic\n")} {
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) { checkMetadataParity(t, data) })
}
