package input

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit22EnvelopeSchemaAndSurrogates(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/hook/audit22-invalid.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name, Payload string
			Deny          bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.ToSlash(t.TempDir())
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(strings.ReplaceAll(tc.Payload, "@CWD@", cwd)))
			if (err != nil) != tc.Deny {
				t.Errorf("invalid=%v want=%v", err != nil, tc.Deny)
			}
		})
	}
}
