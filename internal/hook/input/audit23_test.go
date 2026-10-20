package input

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAudit23StructuralBounds(t *testing.T) {
	const head = `{"tool_name":"Read","cwd":"/synthetic","tool_input":{"file_path":"public.txt"},"metadata":`
	keys := func(n int) string {
		var b strings.Builder
		b.WriteString(head + "{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d":0`, i)
		}
		return b.String() + "}}"
	}
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		// The fixed envelope contains five keys and twenty punctuation/scalar
		// tokens. These boundaries match the permanent Bash audit23 cases.
		{"keys limit", keys(MaxKeys - 5), true},
		{"keys overflow", keys(MaxKeys - 4), false},
		{"global keys limit", head + "[" + strings.TrimSuffix(strings.Repeat(`{"k":0},`, MaxKeys-5), ",") + "]}", true},
		{"global keys overflow", head + "[" + strings.TrimSuffix(strings.Repeat(`{"k":0},`, MaxKeys-4), ",") + "]}", false},
		{"tokens limit", head + "[{}," + strings.Repeat("0,", 16371) + "0]}", true},
		{"tokens overflow", head + "[" + strings.Repeat("0,", 16373) + "0]}", false},
		{"depth limit", head + strings.Repeat("[", MaxDepth-1) + "0" + strings.Repeat("]", MaxDepth-1) + "}", true},
		{"depth overflow", head + strings.Repeat("[", MaxDepth) + "0" + strings.Repeat("]", MaxDepth) + "}", false},
		{"public scalar", head + "1.5e+2}", true},
		{"retained newline cwd tightening", `{"tool_name":"Read","cwd":"/synthetic/public\nsubdirectory","tool_input":{"file_path":"public.txt"}}`, false},
		{"retained newline workdir tightening", `{"tool_name":"Bash","cwd":"/synthetic","tool_input":{"command":"true","workdir":"public\nsubdirectory"}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.body) > MaxBytes {
				t.Fatal("fixture must exercise an under-byte-cap structural bound")
			}
			_, err := Decode(strings.NewReader(tc.body))
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

func TestAudit23PathBounds(t *testing.T) {
	for _, key := range []string{"cwd", "file_path", "notebook_path", "path", "workdir"} {
		for _, n := range []int{32, MaxPathSeparators, MaxPathSeparators + 1, 20000} {
			t.Run(fmt.Sprintf("%s/%d", key, n), func(t *testing.T) {
				fields := map[string]string{"file_path": "public.txt"}
				root := map[string]any{"tool_name": "Read", "cwd": "/synthetic", "tool_input": fields}
				value := strings.Repeat("./", n) + "public.txt"
				if key == "cwd" {
					value = "/" + strings.Repeat("./", n-1) + "synthetic"
					root[key] = value
				} else {
					fields[key] = value
				}
				body, err := json.Marshal(root)
				if err != nil {
					t.Fatal(err)
				}
				_, err = Decode(strings.NewReader(string(body)))
				// U15 retains the separator cap and additionally bounds raw bytes;
				// the old 4096-separator allowance is now intentionally denied.
				if valid := n <= MaxPathSeparators && len(value) <= 4096; (err == nil) != valid {
					t.Fatalf("valid=%v, error=%v", valid, err)
				}
			})
		}
	}
}
