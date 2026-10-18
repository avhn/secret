package policy

import (
	"strings"
	"testing"
)

// Raw stdin witnesses must not count shell quoting as source-language literals.
// Keep the decoded boundary exact, including mixed inner quote kinds and pipes.
func TestAudit29DecodedLiteralBoundary(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		name, code string
		deny       bool
	}{
		{"mixed boundary", strings.Repeat("f('public', \"other\")\n", 128), false},
		{"mixed exceeded", strings.Repeat("f('public', \"other\")\n", 128) + "f('last')\n", true},
		{"protected boundary", strings.Repeat("f('public')\n", 255) + "f('.env')\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for shape, source := range map[string]string{
				"inline":      "python3 -c " + shellLiteral(tc.code),
				"heredoc":     "python3 <<'SYNTHETIC'\n" + tc.code + "SYNTHETIC",
				"here-string": "python3 <<< " + shellLiteral(tc.code),
				"pipe":        "printf '%s' " + shellLiteral(tc.code) + " | python3",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", shape, reason, tc.deny)
				}
				if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s argv: reason=%q want deny=%v", shape, reason, tc.deny)
				}
			}
		})
	}
}
