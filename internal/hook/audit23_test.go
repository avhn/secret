package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only synthetic envelopes reach the guards; candidate commands never execute.
func TestAudit23Envelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit23.json")
}

func TestAudit23EnvelopeBudgets(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	cwd, err := json.Marshal(filepath.ToSlash(root))
	if err != nil {
		t.Fatal(err)
	}
	head := `{"tool_name":"Read","cwd":` + string(cwd) + `,"tool_input":{"file_path":"public.txt"},"metadata":`
	keys := func(n int) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":0`, i)
		}
		return b.String() + "}"
	}
	for _, tc := range []struct {
		name, metadata string
		deny           bool
	}{
		{"keys limit", keys(4091), false},
		{"keys overflow", keys(4092), true},
		{"tokens limit", "[{}," + strings.Repeat("0,", 16371) + "0]", false},
		{"tokens overflow", "[" + strings.Repeat("0,", 16373) + "0]", true},
		{"depth limit", strings.Repeat("[", 127) + "0" + strings.Repeat("]", 127), false},
		{"depth overflow", strings.Repeat("[", 128) + "0" + strings.Repeat("]", 128), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, host := range []string{"claude", "codex"} {
				var output bytes.Buffer
				if err := Decide(host, strings.NewReader(head+tc.metadata+"}"), &output); err != nil {
					t.Fatal(err)
				}
				if deny := strings.Contains(output.String(), `"permissionDecision":"deny"`); deny != tc.deny {
					t.Errorf("%s deny=%v want=%v: %s", host, deny, tc.deny, output.String())
				}
			}
		})
	}
	for _, key := range []string{"file_path", "cwd"} {
		for _, n := range []int{32, 20000} {
			t.Run(fmt.Sprintf("%s/%d", key, n), func(t *testing.T) {
				fields := map[string]string{"file_path": "public.txt"}
				envelope := map[string]any{"tool_name": "Read", "cwd": root, "tool_input": fields}
				if key == "cwd" {
					envelope[key] = filepath.ToSlash(root) + "/" + strings.Repeat("./", n)
				} else {
					fields[key] = strings.Repeat("./", n) + "public.txt"
				}
				body, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				for _, host := range []string{"claude", "codex"} {
					var output bytes.Buffer
					if err := Decide(host, bytes.NewReader(body), &output); err != nil {
						t.Fatal(err)
					}
					if deny := strings.Contains(output.String(), `"permissionDecision":"deny"`); deny != (n > 32) {
						t.Errorf("%s unexpected decision: %s", host, output.String())
					}
				}
			})
		}
	}
}
