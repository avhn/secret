package input

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit20InvalidEnvelopes(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/hook/audit20-invalid.json")
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
	replace := strings.NewReplacer("@CWD@", filepath.ToSlash(t.TempDir()), "@INVALID_UTF8@", string([]byte{0xff}))
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(replace.Replace(tc.Payload)))
			wantInvalid := tc.Deny || tc.Payload == ""
			if (err != nil) != wantInvalid {
				t.Errorf("invalid=%v, want %v", err != nil, wantInvalid)
			}
		})
	}
}
