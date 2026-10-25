package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit22Envelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit22.json")
}

func TestAudit22MalformedEnvelopes(t *testing.T) {
	data, err := os.ReadFile("../../testdata/hook/audit22-invalid.json")
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
	work := filepath.Join(root, "work")
	home := filepath.Join(root, "home")
	for _, dir := range []string{work, home} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			for _, host := range []string{"claude", "codex"} {
				var output bytes.Buffer
				body := strings.ReplaceAll(tc.Payload, "@CWD@", filepath.ToSlash(work))
				requireBashEnvelope(t, []byte(body))
				if err := Decide(host, strings.NewReader(body), &output); err != nil {
					t.Fatal(err)
				}
				if deny := strings.Contains(output.String(), `"permissionDecision":"deny"`); deny != tc.Deny {
					t.Errorf("%s deny=%v want=%v: %s", host, deny, tc.Deny, output.String())
				}
			}
		})
	}
}
