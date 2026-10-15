package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestAudit19GitTemplatesAndSelectors(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	syntheticRepo(t, root, 2, "README.md", "apps/api/.env.example", ".env.sample", "service.env.template")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"git grep -- '*.env*'", false},
		{"git grep TOKEN -- '*.env*'", false},
		{"git grep TOKEN -- 'apps/**/.env*'", false},
		{"git show HEAD:apps/api/.env", true},
		{"git show HEAD:apps/api/.env.example", false},
		{"git show HEAD:.env.sample", false},
		{"git show HEAD:service.env.template", false},
		{"git log HEAD~1:.env.production", true},
		{"git blame HEAD~1:.env.production", true},
		{"git log HEAD:apps/api/.env.example", false},
		{"git log --grep=HEAD:.env.production", false},
		{"git log --grep HEAD:.env.production", false},
		{"git grep TOKEN -- '*.ts'", false},
		{"git grep TOKEN -- '*.env.example'", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			variants := []string{tc.source}
			if tc.deny {
				variants = deniedVariants(tc.source)
			}
			for _, source := range variants {
				if reason := Analyze(source, root, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
				}
			}
		})
	}
	// Broad selectors remain safe only when the bounded index is safe. A
	// matching actual credential entry must not inherit the template exemption.
	syntheticRepo(t, root, 2, "apps/api/.env.production")
	for _, source := range []string{"git grep -- '*.env*'", "git grep TOKEN -- '*.env*'"} {
		for _, variant := range deniedVariants(source) {
			if reason := Analyze(variant, root, home, check); reason == "" {
				t.Errorf("protected indexed selector allowed: %s", variant)
			}
		}
	}
}

func TestAudit19EvalCwd(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	for _, dir := range []string{"home/.aws", "work", "work/web"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".aws", "credentials"), filepath.Join(root, "work", "README.md")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"f() { cd ~/.aws; }; eval f; head credentials", true},
		{"f() { cd ~/.aws; }; command eval f; head credentials", true},
		{"f() { cd ~/.aws; }; builtin eval f; head credentials", true},
		{"eval 'cd ~/.aws'; cat credentials", true},
		{"eval -- 'cd ~/.aws'; cat credentials", true},
		{"eval 'pushd ~/.aws'; cat credentials", true},
		{"eval 'popd'; cat credentials", true},
		{"f() { cd ~/.aws; }; eval 'f'; cat credentials", true},
		{"g() { cd ~/.aws; }; f() { g; }; eval f; cat credentials", true},
		{"eval 'eval cd ~/.aws'; cat credentials", true},
		{"eval 'echo ok'; cat README.md", false},
		{"command eval 'echo ok'; cat README.md", false},
		{"builtin eval 'echo ok'; cat README.md", false},
		{"'eval' 'echo ok'; cat README.md", false},
		{"command 'eval' 'echo ok'; cat README.md", false},
		{"builtin \"eval\" 'echo ok'; cat README.md", false},
		{"f() { echo ok; }; eval f; cat README.md", false},
		{"eval 'cd web'; npm test", false},
		{"(eval 'cd ~/.aws'); cat credentials", false},
		{"eval 'cd ~/.aws' | cat; cat credentials", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			variants := []string{tc.source}
			if tc.deny {
				variants = deniedVariants(tc.source)
			}
			for _, source := range variants {
				if reason := Analyze(source, filepath.Join(root, "work"), home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
				}
			}
		})
	}
}

func TestAudit19ConfiguredListingScopes(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, work, filepath.Join(work, "public")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"kube.yaml", "other.yaml", "README.md", "public/README.md"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`KUBECONFIG=kube.yaml; find . -name "*.yaml" | xargs cat`, true},
		{`KUBECONFIG=kube.yaml; find . -iname "*.YAML" -print0 | xargs -0 head`, true},
		{`KUBECONFIG=kube.yaml; command find . -name "*.yaml" | command xargs cat`, true},
		{`KUBECONFIG=kube.yaml; fd -e yaml . | xargs cat`, true},
		{`KUBECONFIG=kube.yaml; fd -g '*.yaml' -x cat`, true},
		{`KUBECONFIG=kube.yaml; fd -e yaml . -X cat`, true},
		{`KUBECONFIG=kube.yaml; ls . | xargs cat`, true},
		{`KUBECONFIG=kube.yaml; rg --files | xargs cat`, true},
		{`KUBECONFIG=kube.yaml; git ls-files -o | xargs cat`, true},
		{`if true; then KUBECONFIG=kube.yaml; else KUBECONFIG=other.yaml; fi; find . -name '*.yaml' | xargs cat`, true},
		{`KUBECONFIG=kube.yaml; find . -name '*.md' | xargs cat`, false},
		{`KUBECONFIG=kube.yaml; fd -e md . | xargs cat`, false},
		{`KUBECONFIG=kube.yaml; fd -g '*.md' -x cat`, false},
		{`KUBECONFIG=kube.yaml; find public -name '*.yaml' | xargs cat`, false},
		{`KUBECONFIG=kube.yaml; find . -name '*.yaml' | xargs basename`, false},
		{`KUBECONFIG=kube.yaml; fd -e yaml .`, false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("reason=%q, deny=%v", reason, tc.deny)
			}
		})
	}
}

func TestAudit19CredentialSinks(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KUBECONFIG", "")
	for _, tc := range []struct {
		sink string
		deny bool
	}{
		{"docker login --password-stdin", false},
		{"docker login registry.invalid --username=synthetic --password-stdin", false},
		{"docker login -usynthetic --password-stdin registry.invalid", false},
		{"helm registry login registry.invalid --username synthetic --password-stdin", false},
		{"secret stash synthetic TOKEN", false},
		{"docker login --username --password-stdin", true},
		{"docker login -- --password-stdin", true},
		{"helm registry login registry.invalid -- --password-stdin", true},
		{"docker login --password-stdin < README.md", true},
		{"docker login --password-stdin --unsupported", true},
		{"cat | docker login --password-stdin", true},
		{"docker login --password-stdin \"$(echo registry.invalid)\"", true},
	} {
		t.Run(tc.sink, func(t *testing.T) {
			source := "aws ecr get-login-password | " + tc.sink
			reason := Analyze(source, root, root, func(string, string) bool { return false })
			if (reason != "") != tc.deny {
				t.Fatalf("reason=%q, deny=%v", reason, tc.deny)
			}
		})
	}
	if reason := Analyze("aws ecr get-login-password > captured | docker login --password-stdin", root, root, func(string, string) bool { return false }); reason == "" {
		t.Fatal("upstream stdout diversion was allowed")
	}
}

// The retained function-effect model keeps uncertainty for multiple directory
// changes and calls made away from the definition cwd, even with public files.
func TestAudit19FunctionDirectoryEffects(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"web", "sub", "sub/web"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KUBECONFIG", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"f() { cd web; }; cd sub; f; cat config.txt", true},
		{"f() { cd web; cd ..; }; f; cat config.txt", true},
		{"f() { cd web; }; g() { f; }; g; cat config.txt", true},
		{"f() { cd web; }; f; cat README.md", false},
		{"f() { echo ok; }; cd sub; f; cat README.md", false},
		{"f() { (cd web); }; cd sub; f; cat README.md", false},
		{"f() { cd web & }; cd sub; f; cat README.md", false},
		{"f() { cd web; cd ..; }; f; cat " + filepath.ToSlash(filepath.Join(root, "README.md")), false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			for _, source := range deniedVariants(tc.source) {
				if reason := Analyze(source, root, root, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
				}
			}
		})
	}
}

func TestAudit19ConfiguredGitIndex(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	syntheticRepo(t, root, 2, "custom.cfg", "README.md")
	t.Setenv("KUBECONFIG", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"git show HEAD", false},
		{"git show HEAD; KUBECONFIG=custom.cfg; git show HEAD", true},
		{"KUBECONFIG=custom.cfg; git log -p", true},
		{"KUBECONFIG=custom.cfg; git status", false},
		{"KUBECONFIG=absent.cfg; git show HEAD", false},
		{"KUBECONFIG=../custom.cfg; cd sub; git show HEAD", true},
		{"KUBECONFIG=sub/custom.cfg; cd sub; git show HEAD", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			for _, source := range deniedVariants(tc.source) {
				if reason := Analyze(source, root, root, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
				}
			}
		})
	}
	t.Setenv("KUBECONFIG", filepath.Join(root, "custom.cfg"))
	if reason := Analyze("git show HEAD", root, root, check); reason == "" {
		t.Fatal("inherited configured index member allowed")
	}
}
