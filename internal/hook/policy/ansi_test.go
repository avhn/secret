package policy

import "testing"

func TestAudit21ANSILiteral(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		known       bool
	}{
		{`public`, "public", true},
		{`\x2eenv`, ".env", true},
		{`\056env`, ".env", true},
		{"\\" + "u002eenv", ".env", true},
		{`\U0000002eenv`, ".env", true},
		{`\cA`, "\x01", true},
		{`\x`, `\x`, true},
		{`\q`, `\q`, true},
		{`\e\a\b\f\r\v`, "\x1b\a\b\f\r\v", true},
		{`\'\"\\`, "'\"\\", true},
		{`\000`, "", false},
		{`\036`, "", false},
		{`\x1f`, "", false},
		{`\u001d`, "", false},
		{`\c]`, "", false},
		{`\u`, "", false},
		{"\\" + "u00e9", "", false},
		{`\`, "", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, known := ansiLiteral(tc.input)
			if known != tc.known || known && got != tc.want {
				t.Errorf("got %q, known=%v; want %q, known=%v", got, known, tc.want, tc.known)
			}
		})
	}
}
