package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestM21OverdenialEnvelopes(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	for _, name := range []string{".env", "app.secret", "README.md"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	config, err := filepath.Abs("../../examples/ripgreprc")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RIPGREP_CONFIG_PATH", config)
	for _, tc := range []struct {
		argv []string
		deny bool
	}{
		{[]string{"git", "grep", "--no-index", "-q", "T", ".env"}, false},
		{[]string{"git", "grep", "--no-index", "T", ".env"}, true},
		{[]string{"git", "grep", "--no-index", "-q", "-f", ".env", "README.md"}, true},
		{[]string{"python3", "-m", "env"}, false},
		{[]string{"python3", "-m", "env", ".env"}, true},
		{[]string{"python3", "-m", "dotenv", "get", "KEY"}, true},
		{[]string{"python3", "-m", "keyring", "get", "SVC", "USER"}, true},
		{[]string{"env"}, true},
		{[]string{"rg", "--passthru", "-q", "T", ".env"}, false},
		{[]string{"rg", "-l", "--passthru", "T", ".env"}, false},
		{[]string{"rg", "--passthru", "T", ".env"}, true},
		{[]string{"rg", "--passthru", "-q", "-f", ".env", "README.md"}, true},
		{[]string{"rg", "-l", "--passthru", "--pre", "cat", "T", ".env"}, true},
		{[]string{"rg", "-g", "{!*.md,*.secret}", "T"}, true},
		{[]string{"rg", "-g", "{*.secret,!*.md}", "T"}, true},
		{[]string{"rg", "--iglob", "{!*.md,*.secret}", "T"}, true},
		{[]string{"rg", "-g", "!*.md", "T"}, false},
	} {
		t.Run(strings.Join(tc.argv, " "), func(t *testing.T) {
			// Quote argv words literally for the source route; braces remain a
			// ripgrep selector rather than becoming shell brace expansion.
			words := make([]string, len(tc.argv))
			for i, word := range tc.argv {
				words[i] = "'" + strings.ReplaceAll(word, "'", "'\\''") + "'"
			}
			for _, command := range []any{tc.argv, strings.Join(words, " ")} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, tc.deny)
			}
		})
	}
}
