package patch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecision(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(work, 0700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"alias.txt": ".env", "parent": "../.secrets/sub", "loop": "loop"} {
		if err := os.Symlink(target, filepath.Join(work, name)); err != nil {
			t.Fatal(err)
		}
	}
	wrap := func(header string) string { return "*** Begin Patch\n" + header + "\n*** End Patch" }
	cases := []struct {
		name, text, workdir, want string
	}{
		{"add", wrap("*** Add File: .env\n+synthetic"), "work", protectedReason},
		{"update", wrap("*** Update File: .aws/credentials\n@@\n+synthetic"), "work", protectedReason},
		{"delete", wrap("*** Delete File: ../.netrc"), "work", protectedReason},
		{"move source", wrap("*** Update File: .env\n*** Move to: safe.go"), "work", protectedReason},
		{"move destination", wrap("*** Update File: safe.go\n*** Move to: .env"), "work", protectedReason},
		{"alias", wrap("*** Add File: alias.txt"), "work", protectedReason},
		{"parent alias", wrap("*** Update File: parent/../credential.secret"), "work", protectedReason},
		{"loop", wrap("*** Delete File: loop"), "work", protectedReason},
		{"unicode", wrap("*** Add File: 配置/秘密.secret"), "work", protectedReason},
		{"unicode safe", wrap("*** Add File: 配置/普通.go"), "work", ""},
		{"CRLF", strings.ReplaceAll(wrap("*** Update File: safe.go\n*** Move to: .env"), "\n", "\r\n"), "work", protectedReason},
		{"safe", wrap("*** Add File: .env.example\n+synthetic"), "work", ""},
		{"safe move", wrap("*** Update File: safe.go\n*** Move to: other.go"), "work", ""},
		{"absolute workdir", wrap("*** Delete File: .env"), work, protectedReason},
		{"missing begin", "*** Add File: safe.go", "work", invalidReason},
		{"missing end", "*** Begin Patch\n*** Add File: safe.go", "work", invalidReason},
		{"unknown header", wrap("*** Rename File: safe.go"), "work", invalidReason},
		{"empty name", wrap("*** Add File: "), "work", invalidReason},
		{"ambiguous name", wrap("*** Add File: safe.go "), "work", invalidReason},
		{"move without source", wrap("*** Move to: safe.go"), "work", invalidReason},
		{"repeated move", wrap("*** Update File: safe.go\n*** Move to: other.go\n*** Move to: third.go"), "work", invalidReason},
		{"multiple begins", "*** Begin Patch\n*** Begin Patch\n*** Add File: safe.go\n*** End Patch", "work", invalidReason},
		{"text after end", wrap("*** Add File: safe.go") + "\n+extra", "work", invalidReason},
		{"embedded carriage return", wrap("*** Add File: safe\r.go"), "work", invalidReason},
		{"protected embedded carriage return", wrap("*** Add File: .env\r.secret"), "work", invalidReason},
		{"indented protected header", wrap("*** Add File: safe.go\n+safe\n *** Update File: .env"), "work", protectedReason},
		{"indented delete section header", wrap("*** Delete File: safe.go\n\t*** Update File: .env"), "work", protectedReason},
		{"indented safe header", wrap("  *** Add File: safe.go\n+safe"), "work", ""},
		{"oversized", wrap("*** Add File: safe.go\n+" + strings.Repeat("s", maxBytes)), "work", invalidReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decision(tc.text, root, tc.workdir, root); got != tc.want {
				t.Fatalf("reason=%q, want %q", got, tc.want)
			}
		})
	}
}

func FuzzPatch(f *testing.F) {
	for _, seed := range []string{
		"*** Begin Patch\n*** Add File: .env\n+synthetic\n*** End Patch",
		"*** Begin Patch\r\n*** Update File: safe.go\r\n*** Move to: 普通.go\r\n*** End Patch",
		"*** Add File: safe.go", "*** Begin Patch\n*** Delete File: ../.netrc\n*** End Patch",
		strings.Repeat("x", maxBytes+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		got := Decision(text, t.TempDir(), "", "/synthetic")
		if got != "" && got != protectedReason && got != invalidReason {
			t.Fatalf("unexpected reason %q", got)
		}
		if len(text) > maxBytes && got == "" {
			t.Fatal("oversized patch allowed")
		}
	})
}
