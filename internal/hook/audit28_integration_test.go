package hook

import (
	"strings"
	"testing"
)

func TestAudit28IntegrationGrepBudgets(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	for _, mode := range []string{"content", "files_with_matches"} {
		for _, tc := range []struct {
			name, glob, typ string
			deny            bool
		}{
			{"components_limit", strings.Repeat("./", 128) + "*.ts", "", false},
			{"components_over", strings.Repeat("./", 129) + "*.ts", "", true},
			{"type_components_over", "", strings.Repeat("./", 129) + "ts", true},
			{"type_bytes_over", "", strings.Repeat("t", 4097), true},
			{"nested_braces", strings.Repeat("{a,", 300) + ".env" + strings.Repeat("}", 300), "", true},
			{"safe_braces", "*.{ts,tsx}", "", false},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "synthetic", "glob": tc.glob, "type": tc.typ, "output_mode": mode}, tc.deny)
			})
		}
	}
}

func TestAudit28IntegrationBraceDepth(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	for _, tc := range []struct {
		name, command string
		deny          bool
	}{
		{"at_limit", "echo " + strings.Repeat("{", 64) + "x" + strings.Repeat("}", 64), false},
		{"over_limit", "echo " + strings.Repeat("{", 65) + "x" + strings.Repeat("}", 65), true},
		{"quoted_data", "printf %s '" + strings.Repeat("{", 80) + "x" + strings.Repeat("}", 80) + "'", false},
		{"escaped_data", "echo " + strings.Repeat(`\{`, 80) + "x" + strings.Repeat(`\}`, 80), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit28ToolCheck(t, "Bash", work, map[string]any{"command": tc.command}, tc.deny)
			audit28ToolCheck(t, "Bash", work, map[string]any{"command": []string{"bash", "-c", tc.command}}, tc.deny)
		})
	}
}
