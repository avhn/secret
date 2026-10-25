//go:build windows

package hook

import "testing"

// Restoring Bash policy's physical traversal must not route native shell
// requests into that analyzer. Both hosts still deny every former skip variant.
func TestWindowsLexicalTraversalShellVariantsDeny(t *testing.T) {
	_, work := windowsHookFixture(t)
	for _, command := range []string{
		"paste awsx/../credentials",
		"command paste awsx/../credentials",
		"'paste' awsx/../credentials",
		"\"paste\" awsx/../credentials",
		"$'paste' awsx/../credentials",
		"paste 'awsx/../credentials'",
		"paste \"awsx/../credentials\"",
		"paste $'awsx/../credentials'",
	} {
		t.Run(command, func(t *testing.T) {
			windowsHookCheck(t, "Bash", work, map[string]any{"command": command}, windowsShellReason)
		})
	}
}
