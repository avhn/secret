package policy

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// These are analyzer inputs only. No producer, interpreter or probed command
// runs, and configured credential targets deliberately need not exist.
func TestAudit20DecodedInterpreterProducers(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(key, "")
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, config := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, inherited := range []bool{true, false} {
			prefix := config + "=custom.cfg; "
			if inherited {
				t.Setenv(config, filepath.Join(root, "custom.cfg"))
				prefix = ""
			} else {
				t.Setenv(config, "")
			}
			for _, tc := range []struct {
				name string
				deny bool
			}{
				{"custom.cfg", true},
				{"./custom.cfg", true},
				{"README.md", false},
			} {
				for _, interpreter := range []struct{ name, body string }{
					{"python3", `print(open("` + tc.name + `").read())`},
					{"node", `console.log(require("fs").readFileSync("` + tc.name + `", "utf8"))`},
					{"ruby", `puts File.read("` + tc.name + `")`},
					{"perl", `open my $f, "<", "` + tc.name + `"; print <$f>`},
				} {
					body := interpreter.body
					var escaped strings.Builder
					for _, r := range body {
						escaped.WriteByte('\\')
						escaped.WriteRune(r)
					}
					for _, quoted := range []string{
						"'" + body + "'",
						`"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`").Replace(body) + `"`,
						"$'" + strings.NewReplacer(`\`, `\\`, "'", `\'`).Replace(body) + "'",
						escaped.String(),
					} {
						for _, producer := range []string{"printf '%s' ", "echo ", "cat <<< "} {
							for _, wrapper := range []string{"", "command ", "builtin "} {
								for _, recipient := range []string{interpreter.name, "command " + interpreter.name, "'" + interpreter.name + "'"} {
									source := prefix + wrapper + producer + quoted + " | " + recipient
									if reason := Analyze(source, root, root, check); (reason != "") != tc.deny {
										t.Errorf("%s inherited=%v: %s: reason=%q, deny=%v", config, inherited, source, reason, tc.deny)
									}
								}
							}
						}
					}
				}
			}
		}
		t.Setenv(config, "")
	}
}
