package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit20InvalidEnvelopes(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hook/audit20-invalid.json")
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
	root := t.TempDir()
	t.Setenv("HOME", root)
	replace := strings.NewReplacer("@CWD@", filepath.ToSlash(root), "@INVALID_UTF8@", string([]byte{0xff}))
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			for _, host := range []string{"claude", "codex"} {
				requireBashEnvelope(t, []byte(replace.Replace(tc.Payload)))
				var out bytes.Buffer
				if err := Decide(host, strings.NewReader(replace.Replace(tc.Payload)), &out); err != nil {
					t.Fatal(err)
				}
				if tc.Deny {
					var decision map[string]any
					if !json.Valid(out.Bytes()) || json.Unmarshal(out.Bytes(), &decision) != nil || !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
						t.Errorf("%s: malformed input lacked explicit JSON denial: %q", host, out.String())
					}
				} else if out.Len() != 0 {
					t.Errorf("%s: valid or zero-byte input denied: %s", host, out.String())
				}
			}
		})
	}
}
