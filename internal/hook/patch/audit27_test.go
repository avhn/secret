package patch

import "testing"

func TestAudit27UpdateEOF(t *testing.T) {
	root := t.TempDir()
	update := "*** Update File: public.txt\n@@\n-old\n+new\n"
	for _, tc := range []struct {
		name, body string
		deny       bool
	}{
		{"update eof", update + "*** End of File", false},
		{"next section", update + "*** End of File\n*** Add File: next.txt\n+public", false},
		{"protected next section", update + "*** End of File\n*** Add File: .env\n+synthetic", true},
		{"no hunk", "*** Update File: public.txt\n*** End of File", true},
		{"add eof", "*** Add File: public.txt\n+new\n*** End of File", true},
		{"delete eof", "*** Delete File: public.txt\n*** End of File", true},
		{"duplicate", update + "*** End of File\n*** End of File", true},
		{"body after eof", update + "*** End of File\n+extra", true},
		{"hunk after eof", update + "*** End of File\n@@\n+extra", true},
		{"move after hunk", update + "*** Move to: next.txt", true},
		{"move after eof", update + "*** End of File\n*** Move to: next.txt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, end := range []string{"", "\n"} {
				text := "*** Begin Patch\n" + tc.body + "\n*** End Patch" + end
				if reason := Decision(text, root, "", root); (reason != "") != tc.deny {
					t.Errorf("reason=%q want deny=%v", reason, tc.deny)
				}
			}
		})
	}
}
