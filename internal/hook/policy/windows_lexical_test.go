package policy

import (
	"encoding/json"
	"os"
	"testing"
)

type corpusVariant struct {
	name  string
	index int
}

// The explicit list is shared with the native hook boundary test. Check it on
// every platform so removed cases, reordered variants and changed text fail even
// without a Windows runner. Never infer exceptions from command/path patterns.
func windowsLexicalVariants(t *testing.T, cases []corpusCase) map[corpusVariant]string {
	t.Helper()
	data, err := os.ReadFile("../../../testdata/hook/windows-lexical-variants.json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Name    string `json:"case"`
		Variant int    `json:"variant"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 {
		t.Fatalf("Windows lexical classification has %d entries, want exactly 8", len(entries))
	}
	classified := make(map[corpusVariant]string)
	for _, entry := range entries {
		key := corpusVariant{entry.Name, entry.Variant}
		if _, exists := classified[key]; exists {
			t.Fatalf("duplicate Windows lexical classification: %s variant %d", entry.Name, entry.Variant)
		}
		matches := 0
		for _, tc := range cases {
			if tc.Name != entry.Name {
				continue
			}
			matches++
			variants := deniedVariants(tc.Command)
			if entry.Variant < 0 || entry.Variant >= len(variants) {
				t.Fatalf("listed Windows lexical variant no longer exists: %s variant %d", entry.Name, entry.Variant)
			}
			if variants[entry.Variant] != entry.Command {
				t.Fatalf("listed Windows lexical variant changed: %s variant %d", entry.Name, entry.Variant)
			}
		}
		if matches != 1 {
			t.Fatalf("listed Windows lexical case has %d matches: %s", matches, entry.Name)
		}
		classified[key] = entry.Command
	}
	return classified
}

func TestWindowsLexicalVariantsMatchCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/hook/denied-commands.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct{ Cases []corpusCase }
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	windowsLexicalVariants(t, corpus.Cases)
}
