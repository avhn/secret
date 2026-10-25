package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/feature"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestChildEnvironment(t *testing.T) {
	selection := store.Selection{Keys: []string{"A", "B", "C"}, Matched: map[string]store.Record{"A": {Value: []byte("last")}, "B": {Value: []byte("selected")}}, AllValues: [][]byte{[]byte("old"), []byte("last")}}
	ambient := []string{"HOME=/tmp", "A=ambient", "B=ambient", "C=ambient", "OPT=ambient", "KEEP=ambient", "SECRET_CHILD_DATA=ambient"}
	for _, tc := range []struct {
		name               string
		required, optional []string
		want               string
		failed             bool
	}{
		{"default", nil, nil, "HOME=/tmp,A=last,B=selected,KEEP=ambient", false},
		{"required", []string{"A"}, nil, "HOME=/tmp,A=last,KEEP=ambient,OPT=ambient", false},
		{"optional", nil, []string{"B", "OPT"}, "HOME=/tmp,B=selected,KEEP=ambient", false},
		{"absent", []string{"C"}, nil, "", true},
		{"invalid", nil, []string{"2BAD"}, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := childEnvironment(ambient, selection, tc.required, tc.optional, "/tmp/fallback.store")
			if (e != nil) != tc.failed {
				t.Fatalf("error: %v", e)
			}
			if !tc.failed {
				// Ambient surviving keys retain order; selected keys append in store order.
				want := strings.Split(tc.want, ",")
				if tc.name == "required" {
					want = []string{"HOME=/tmp", "OPT=ambient", "KEEP=ambient", "A=last"}
				}
				if tc.name == "default" {
					want = []string{"HOME=/tmp", "OPT=ambient", "KEEP=ambient", "A=last", "B=selected"}
				}
				if tc.name == "optional" {
					want = []string{"HOME=/tmp", "KEEP=ambient", "B=selected"}
				}
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Fatalf("got %q want %q", got, want)
				}
			}
		})
	}
}

func TestChildEnvironmentFilePrecedence(t *testing.T) {
	first, _ := store.Select([]store.Record{{Key: "A", Value: []byte("earlier")}, {Key: "B", Value: []byte("first-only")}}, store.Selectors{})
	later, _ := store.Select([]store.Record{{Key: "A", Value: []byte("later"), Labels: map[string]string{"env": "dev"}}, {Key: "A", Value: []byte("unselected"), Labels: map[string]string{"env": "prod"}}}, store.Selectors{"env": "dev"})
	missing, _ := store.Select([]store.Record{{Key: "A", Value: []byte("unselected"), Labels: map[string]string{"env": "prod"}}}, store.Selectors{"env": "dev"})
	for _, tc := range []struct {
		name       string
		selections []store.Selection
		want       string
	}{
		{"later selected", []store.Selection{first, later}, "A=later,B=first-only"},
		{"later unselected", []store.Selection{first, missing}, "A=earlier,B=first-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := childEnvironment(nil, store.Merge(tc.selections...), nil, nil, "fallback")
			if e != nil {
				t.Fatal(e)
			}
			if strings.Join(got, ",") != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func syntheticTemplateHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(testutil.TempDir(t))
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func TestParseLaunchTemplate(t *testing.T) {
	loc := store.Locator{}
	storeRef := "file:" + filepath.Join(t.TempDir(), "synthetic.store")
	for _, tc := range []struct {
		options []string
		want    string
		bad     bool
	}{
		{[]string{"--template-file", "input.tmpl"}, "input.tmpl", false},
		{[]string{"--template-file=input.tmpl"}, "input.tmpl", false},
		{[]string{"--template-file="}, "", true},
		{[]string{"--template-file", "a", "--template-file", "b"}, "", true},
		{[]string{"--output", "elsewhere"}, "", true},
		{[]string{"--output-dir", "elsewhere"}, "", true},
		{[]string{"--template-output-dir", "elsewhere"}, "", true},
	} {
		args := append([]string{"-f", storeRef}, tc.options...)
		args = append(args, "--", "synthetic-child")
		o, err := parseLaunch(args, loc)
		if (err != nil) != tc.bad || !tc.bad && o.templateFile != tc.want {
			t.Fatalf("template parse error %v", err)
		}
	}
}

func TestLaunchTemplateSelectionAndCleanup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix supervised launch")
	}
	home := syntheticTemplateHome(t)
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", syntheticTemplateHome(t))
	t.Setenv("SECRET_TEMPLATE_FILE", "/synthetic/ambient-path")
	storePath := filepath.Join(home, "synthetic.store")
	if err := os.WriteFile(storePath, []byte("A=synthetic-default\nB=synthetic-other\n[env=dev]\nA=synthetic-selected\n[env=prod]\nA=synthetic-unselected\n"), 0600); err != nil {
		t.Fatal(err)
	}
	templatePath := filepath.Join(home, "synthetic.tmpl")
	if err := os.WriteFile(templatePath, []byte("config={{A}}"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	status := Main([]string{"run", "-f", "file:" + storePath, "--env", "dev", "--key", "A", "--template-file", templatePath, "--", "sh", "-c", `printf '%s\n' "$SECRET_TEMPLATE_FILE"; cat "$SECRET_TEMPLATE_FILE"; printf '\nsynthetic-unselected\n'; test -z "${B+x}"`}, os.Stdin, &out, &errOut)
	if status != 0 || errOut.Len() != 0 {
		t.Fatalf("status %d, stderr %q", status, errOut.String())
	}
	path, rest, ok := strings.Cut(out.String(), "\n")
	if !ok || rest != "config=<redacted>\n<redacted>\n" {
		t.Fatal("template or all-loaded-value redaction failed")
	}
	if filepath.Dir(filepath.Dir(path)) != filepath.Join(home, ".secrets", ".rendered") {
		t.Fatal("child did not receive fixed namespace path")
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("payload directory survived child exit")
	}
}

func TestLaunchTemplateFailures(t *testing.T) {
	for _, kind := range []string{"exec", "missing placeholder", "unselected key", "spawn", "filter", "pipe drain", "oversize", "directory"} {
		t.Run(kind, func(t *testing.T) {
			home := syntheticTemplateHome(t)
			t.Setenv("HOME", home)
			t.Setenv("SECRETS_DIR", filepath.Join(home, "overridden"))
			storePath := filepath.Join(home, "synthetic.store")
			templatePath := filepath.Join(home, "synthetic.tmpl")
			if err := testutil.WriteFile(storePath, []byte("A=synthetic-selected\nB=synthetic-other\n"), 0600); err != nil {
				t.Fatal(err)
			}
			input := []byte("{{A}}")
			if kind == "missing placeholder" {
				input = []byte("{{MISSING}}")
			}
			if kind == "unselected key" {
				input = []byte("{{B}}")
			}
			if kind == "oversize" {
				input = bytes.Repeat([]byte("x"), feature.MaxTemplateBytes+1)
			}
			if err := testutil.WriteFile(templatePath, input, 0600); err != nil {
				t.Fatal(err)
			}
			if kind == "directory" {
				templatePath = home
			}
			mode := "run"
			if kind == "exec" {
				mode = "exec"
			}
			child := []string{"sh", "-c", `cat "$SECRET_TEMPLATE_FILE"`}
			if kind == "spawn" {
				child = []string{"/synthetic/missing-command"}
			}
			if kind == "pipe drain" {
				child = []string{"sh", "-c", `sleep 10 & cat "$SECRET_TEMPLATE_FILE"`}
			}
			child = templateFailureChild(kind, home, child)
			args := []string{mode, "-f", "file:" + storePath, "--key", "A", "--template-file", templatePath, "--"}
			var out, errOut bytes.Buffer
			var output interface{ Write([]byte) (int, error) } = &out
			if kind == "filter" {
				output = failingWriter{}
			}
			status := Main(append(args, child...), os.Stdin, output, &errOut)
			if status != 1 || errOut.Len() == 0 {
				t.Fatalf("status %d stderr %q", status, errOut.String())
			}
			if bytes.Contains(errOut.Bytes(), []byte("synthetic-selected")) || bytes.Contains(errOut.Bytes(), []byte("synthetic-other")) {
				t.Fatal("diagnostic contains a value")
			}
			entries, err := os.ReadDir(filepath.Join(home, ".secrets", ".rendered"))
			if err != nil && !errors.Is(err, os.ErrNotExist) || len(entries) != 0 {
				t.Fatal("failure left a rendered payload")
			}
		})
	}
}
