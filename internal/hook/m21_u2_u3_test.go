package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestM21U2U3Envelopes(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../testdata/hook/m21-u2-u3.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct{ Name, Source string }
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			for _, command := range []any{tc.Source, []string{"bash", "-c", tc.Source}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, true)
			}
		})
	}
	for _, source := range []string{
		"coproc true >public.out", "coproc 'then' public", "coproc NAME { true; }",
		"coproc apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\nPATCH",
		"env -Sapply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\nPATCH",
		"{ env apply_patch; } <<'PATCH'\n*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\nPATCH",
		"cat public.patch | git apply --check", "patch --help",
	} {
		t.Run(source, func(t *testing.T) {
			for _, command := range []any{source, []string{"bash", "-c", source}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, false)
			}
		})
	}
}
