package patch

import (
	"fmt"
	"strings"
	"testing"
)

func TestM21PatchGrammar(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name, body string
		invalid    bool
	}{
		{"add", "*** Add File: public\n+new\n+", false},
		{"empty add", "*** Add File: public", false},
		{"body tabs", "*** Add File: public\n+\tindented", false},
		{"header-like data", "*** Add File: public\n+*** Delete File: .env", false},
		{"update tabs", "*** Update File: public\n@@\n \tcontext\n-\told\n+\tnew", false},
		{"delete", "*** Delete File: public", false},
		{"update", "*** Update File: public\n@@\n old\n-old\n+new", false},
		{"multiple hunks", "*** Update File: public\n@@ anchor\n-old\n+new\n@@ next\n context", false},
		{"move update", "*** Update File: public\n*** Move to: next\n@@\n-old\n+new", false},
		{"eof next section", "*** Update File: public\n@@\n-old\n+new\n*** End of File\n*** Delete File: next", false},
		{"add unprefixed", "*** Add File: public\nnew", true},
		{"add context", "*** Add File: public\n context", true},
		{"add removal", "*** Add File: public\n-old", true},
		{"add hunk", "*** Add File: public\n@@\n+new", true},
		{"delete body", "*** Delete File: public\n+new", true},
		{"empty update", "*** Update File: public", true},
		{"move only", "*** Update File: public\n*** Move to: next", true},
		{"implicit first hunk", "*** Update File: public\n-old\n+new", false},
		{"upstream implicit context", "*** Update File: public\n import foo\n+bar", false},
		{"implicit then explicit", "*** Update File: public\n-old\n+new\n@@ next\n context", false},
		{"implicit move update", "*** Update File: public\n*** Move to: next\n-old\n+new", false},
		{"implicit empty context", "*** Update File: public\n\n+new", false},
		{"blank after eof", "*** Update File: public\n@@\n+new\n*** End of File\n", false},
		{"indented public context header", "*** Update File: public\n *** Add File: other\n+new", false},
		{"empty hunk", "*** Update File: public\n@@", true},
		{"empty initial hunk", "*** Update File: public\n@@\n@@\n+new", true},
		{"empty final hunk", "*** Update File: public\n@@\n+new\n@@", true},
		{"unprefixed update", "*** Update File: public\n@@\nnew", true},
		{"blank update", "*** Update File: public\n@@\n", false},
		{"bad hunk marker", "*** Update File: public\n@@bad\n+new", true},
		{"empty hunk anchor", "*** Update File: public\n@@ \n+new", false},
		{"empty eof hunk", "*** Update File: public\n@@\n*** End of File", true},
		{"move after body", "*** Update File: public\n@@\n+new\n*** Move to: next", true},
		{"move in add", "*** Add File: public\n*** Move to: next", true},
		{"indented section", " *** Add File: public\n+new", false},
		{"duplicate end", "*** Delete File: public\n*** End Patch", true},
		{"incomplete section before delete", "*** Update File: public\n@@\n*** Delete File: next", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, suffix := range []string{"", "\n"} {
				text := "*** Begin Patch\n" + tc.body + "\n*** End Patch" + suffix
				if got := Decision(text, root, "", root); (got != "") != tc.invalid {
					t.Errorf("reason=%q want invalid=%v", got, tc.invalid)
				}
			}
		})
	}
}

func TestM21PatchHeaderBytes(t *testing.T) {
	root := t.TempDir()
	t.Run("later raw overflow precedes metadata", func(t *testing.T) {
		text := "*** Begin Patch\n*** Delete File: .env\n*** Delete File: " + strings.Repeat("a", 256) + "\n*** End Patch"
		if got := Decision(text, root, "", root); got != invalidReason {
			t.Fatalf("reason=%q want fixed recovery guidance", got)
		}
	})
	for _, op := range []string{"Add File", "Delete File", "Update File", "Move to"} {
		for _, tc := range []struct {
			name, value string
			invalid     bool
		}{
			{"component cap", strings.Repeat("a", 255), false},
			{"component overflow", strings.Repeat("a", 256), true},
			{"unicode cap", strings.Repeat("界", 85), false},
			{"unicode overflow", strings.Repeat("界", 86), true},
			{"path cap", strings.Repeat("a/", 2047) + "ab", false},
			{"path overflow", strings.Repeat("a/", 2048) + "a", true},
			{"raw dotdot", strings.Repeat("a", 256) + "/../public", true},
		} {
			t.Run(op+"/"+tc.name, func(t *testing.T) {
				header := "*** " + op + ": " + tc.value
				if op == "Move to" {
					header = "*** Update File: public\n" + header
				}
				if op == "Move to" || op == "Update File" {
					header += "\n@@\n-old\n+new"
				}
				got := Decision("*** Begin Patch\n"+header+"\n*** End Patch", root, "", root)
				if tc.invalid && got != invalidReason {
					t.Errorf("reason=%q want fixed recovery guidance", got)
				}
				// At-cap paths need not exist or fit the native filesystem's
				// anchored-path cap. Grammar acceptance is tested separately.
			})
		}
	}
	for control := byte(0); control <= 0x7f; control++ {
		if control >= 0x20 && control != 0x7f {
			continue
		}
		for _, template := range []string{
			"*** Begin Patch%s\n*** Delete File: public\n*** End Patch",
			"*** Begin Patch\n*** Delete File: pub%slic\n*** End Patch",
			"*** Begin Patch\n*** Delete File: public%s\n*** End Patch",
			"*** Begin Patch\n*** Delete File: public\n*** End Patch%s",
			"*** Begin Patch\n*** Update File: public\n@@ anchor%s\n-old\n+new\n*** End Patch",
		} {
			// LF is framing, not a byte inside a header; doubled framing is
			// malformed in these templates except the permitted final newline.
			if control == '\n' {
				continue
			}
			t.Run(fmt.Sprintf("control-%02x/%s", control, template), func(t *testing.T) {
				text := fmt.Sprintf(template, string(control))
				if got := Decision(text, root, "", root); got != invalidReason {
					t.Errorf("reason=%q want fixed recovery guidance", got)
				}
			})
		}
	}
}
