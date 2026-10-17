package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

func TestAuditBoundaries(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"safe", ".git", ".secrets"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"app.env", ".secrets/store", "safe/code.go"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(file)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool {
		if filepath.Base(name) == name {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", root)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", root)
	}
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"for i in ; do cd safe; done; paste app.env", true},
		{"if false; then cd safe; else paste app.env; fi", true},
		{"f() { cd safe; }; paste app.env", true},
		{"cd safe || paste app.env", true},
		{"cd safe; paste code.go", false},
		{"export CDPATH=safe; cd other; paste store", true},
		{"export BASH_ENV=app.env; bash -c :", true},
		{"BASH_ENV=$UNKNOWN bash -c :", true},
		{"BASH_ENV=app.env bash -xc : | secret stash service KEY", true},
		{"PROMPT_COMMAND=$UNKNOWN bash -i", true},
		{"PROMPT_COMMAND='echo safe' bash -i", true},
		{"dotenv -e app.env paste app.env", true},
		{"dotenv -e app.env --unsupported npm start", true},
		{"dotenv -e app.env -- npm start", false},
		{"tar -cf output.tar safe", false},
		{"tar cfv output.tar safe", false},
		{"tar -cfoutput.tar safe", false},
		{"tar -cf output.tar .secrets -C safe code.go", true},
		{"tar -cf output.tar missing", true},
		{"tar -cf output.tar .", true},
		{"tar --create --file=out.tar .secrets", true},
		{"tar -xOf a.tar app.env", true},
		{"unzip -c a.zip app.env", true},
		{"git show HEAD -- safe/code.go", true},
		{"git show HEAD -- .", true},
		{"git log --patch", true},
		{"git cat-file -p HEAD:app.env", true},
		{"git grep -l --not-a-git-option pattern", true},
		{"jq --arg label app.env -n '$label'", false},
		{"jq -n --arg label x \"$label\"", true},
		{"jq -n '$ENV' | secret stash service KEY", false},
		{"gh auth status -t", true},
		{"gh auth status", false},
		{"kubectl config view", false},
		{"make --print-data-base", true},
		{"npm config list --json", true},
		{"npm config get registry", false},
		{"envsubst | secret stash service KEY", false},
		{"echo safe\x7f", true},
		{"echo safe\x02", true},
		{`bash -c $'ps axe #\x01'`, true},
		{"echo safe\n\techo safe", false},
		{"apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: safe.go\n+safe\n*** End Patch\nEOF", false},
		{"apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: safe.go\n+safe\n *** Delete File: app.env\n*** End Patch\nEOF", true},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if reason := Analyze(tc.source, root, root, check); (reason != "") != tc.deny {
				t.Errorf("deny=%v want %v: %s", reason != "", tc.deny, reason)
			}
		})
	}
	if got := Analyze("echo safe", "relative", root, check); got != roles.Indeterminate {
		t.Errorf("relative cwd reason %q", got)
	}
	if got := AnalyzeArgv([]string{"echo", "safe\x01"}, root, root, check); got != roles.Indeterminate {
		t.Errorf("argv control reason %q", got)
	}
}
