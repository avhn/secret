package patch

import "testing"

// Cases mirror parser.rs and streaming_parser.rs in openai/codex, with explicit
// retained security-policy exclusions tested separately from syntax errors.
func TestM21UpstreamFraming(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	public := "*** Begin Patch\n*** Update File: public\n old\n+new\n*** End Patch"
	protected := "*** Begin Patch\n*** Update File: .env\n old\n+new\n*** End Patch"
	for _, tc := range []struct {
		name, text string
		deny       bool
	}{
		{"implicit first chunk", public, false},
		{"protected implicit chunk", protected, true},
		{"spaces around framing", " *** Begin Patch  \n *** Add File: public\n+new\n *** End Patch  ", false},
		{"public indented header context", "*** Begin Patch\n*** Update File: public\n *** Add File: other\n+new\n*** End Patch", false},
		{"protected ambiguous header context", "*** Begin Patch\n*** Update File: public\n *** Add File: .env\n+new\n*** End Patch", true},
		{"literal heredoc", "<<EOF\n" + public + "\nEOF", false},
		{"single quoted literal heredoc", "<<'EOF'\n" + public + "\nEOF\n", false},
		{"double quoted literal heredoc", "<<\"EOF\"\n" + public + "\nEOF", false},
		{"protected literal heredoc", "<<'EOF'\n" + protected + "\nEOF", true},
		{"no expansion in literal wrapper", "<<EOF\n*** Begin Patch\n*** Add File: public\n+$(cat .env)\n*** End Patch\nEOF", false},
		{"ambiguous wrapper suffix", "<<EOF\n" + public + "\notherEOF", true},
		{"unsupported delimiter", "<<PATCH\n" + public + "\nPATCH", true},
		{"unterminated wrapper", "<<EOF\n" + public, true},
		{"wrapper trailing data", "<<EOF\n" + public + "\nEOF\n+extra", true},
		{"empty update", "*** Begin Patch\n*** Update File: public\n*** End Patch", true},
		{"retained empty project Yarn fixture", "*** Begin Patch\n*** Update File: .yarnrc.yml\n*** End Patch", true},
		{"project Yarn implicit chunk", "*** Begin Patch\n*** Update File: .yarnrc.yml\n-old\n+new\n*** End Patch", false},
		{"move only", "*** Begin Patch\n*** Update File: public\n*** Move to: next\n*** End Patch", true},
		{"targetless envelope", "*** Begin Patch\n*** End Patch", true},
		{"uncertified environment", "*** Begin Patch\n*** Environment ID: remote\n*** Add File: public\n+new\n*** End Patch", true},
		{"extra outer newline", public + "\n\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Decision(tc.text, root, "", home)
			if (got != "") != tc.deny {
				t.Fatalf("deny=%v reason=%q want=%v", got != "", got, tc.deny)
			}
			if tc.name == "retained empty project Yarn fixture" && got != invalidReason {
				t.Fatal("public Yarn fixture must deny for its empty Update, not its filename")
			}
		})
	}
}
