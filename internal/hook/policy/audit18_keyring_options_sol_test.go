package policy

import (
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/roles"
)

// Keyring commands are synthetic policy input only and are never executed.
func TestAudit18KeyringGlobalOptionsSol(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("RIPGREP_CONFIG_PATH", "")
	for _, prefix := range []string{"keyring", "python -m keyring", "python3 -m keyring"} {
		for _, tc := range []struct {
			args string
			deny bool
		}{
			{"get service user", true},
			{"--mode password get service user", true},
			{"--mode=creds get service", true},
			{"--output json get service user", true},
			{"--output=json get service user", true},
			{"--mode=creds --output=json -bsynthetic.Backend get service", true},
			{"--mode=password --output plain --help", false},
			{"-b synthetic.Backend get service user", true},
			{"-bsynthetic.Backend get service user", true},
			{"-b=synthetic.Backend get service user", true},
			{"--keyring-backend synthetic.Backend get service user", true},
			{"--keyring-backend=synthetic.Backend get service user", true},
			{"-p synthetic get service user", true},
			{"-psynthetic get service user", true},
			{"-p=synthetic get service user", true},
			{"--keyring-path synthetic get service user", true},
			{"--keyring-path=synthetic get service user", true},
			{"-b synthetic.Backend --keyring-path=synthetic get service user", true},
			{"--keyring-path synthetic -bsynthetic.Backend get service user", true},
			{"-psynthetic -- get service user", true},
			{"--help", false},
			{"-h", false},
			{"-b synthetic.Backend --help", false},
			{"--keyring-path=synthetic -h", false},
			{"--help get service user", false},
			{"-b get set service user", false},
			{"--keyring-path get --help", false},
			{"-psynthetic set service get", false},
		} {
			source := prefix + " " + tc.args
			t.Run(source, func(t *testing.T) {
				want := ""
				if tc.deny {
					want = roles.Printer
				}
				if got := Analyze(source, root, root, protected); got != want {
					t.Errorf("shell reason=%q, want %q", got, want)
				}
				if got := AnalyzeArgv(strings.Fields(source), root, root, protected); got != want {
					t.Errorf("argv reason=%q, want %q", got, want)
				}
				if tc.deny {
					if got := Analyze(source+" | secret stash synthetic KEY", root, root, protected); got != "" {
						t.Errorf("direct stash reason=%q, want allow", got)
					}
					if got := Analyze(source+" | cat | secret stash synthetic KEY", root, root, protected); got != roles.Printer {
						t.Errorf("indirect stash reason=%q, want %q", got, roles.Printer)
					}
				}
			})
		}
	}
}
