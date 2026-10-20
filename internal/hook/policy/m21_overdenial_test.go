package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// Commands are analyzer input only. No interpreter or search tool is executed.
func TestM21Overdenials(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	work := filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".env", "app.secret", "README.md"} {
		if err := os.WriteFile(filepath.Join(work, name), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	config, err := filepath.Abs("../../../examples/ripgreprc")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		t.Setenv(name, "")
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	for _, tc := range []struct {
		name, source string
		deny         bool
	}{
		{"git quiet", "git grep --no-index -q T .env", false},
		{"git quiet long", "git grep --no-index --quiet T .env", false},
		{"git names", "git grep --no-index -l T .env", false},
		{"git content", "git grep --no-index T .env", true},
		{"git quiet pattern file", "git grep --no-index -q -f .env README.md", true},
		{"git quiet pager", "git grep --no-index -q -Ocat T .env", true},
		{"git quiet unknown option", "git grep --no-index -q --unknown T .env", true},
		{"git count unchanged", "git grep --no-index -c T .env", true},
		{"python module env", "python3 -m env", false},
		{"python versioned module env", "python3.13 -m env", false},
		{"pypy module env", "pypy3 -m env", false},
		{"python module env wrapper", "timeout 5 python3 -m env", false},
		{"python module public argument", "python3 -m env README.md", false},
		{"python module protected argument", "python3 -m env .env", true},
		{"python module protected redirect", "python3 -m env < .env", true},
		{"python module printer argument", "python3 -m env printenv TOKEN", true},
		{"python module dotenv", "python3 -m dotenv get KEY", true},
		{"python module keyring", "python3 -m keyring get SVC USER", true},
		{"python module dotenv child", "python3 -m dotenv run -- env", true},
		{"environment printer", "env", true},
		{"rg quiet", "rg -q T .env", false},
		{"rg quiet passthru", "rg --passthru -q T .env", false},
		{"rg passthru quiet reverse", "rg -q --passthru T .env", false},
		{"rg names passthru", "rg -l --passthru T .env", false},
		{"rg passthru names reverse", "rg --passthru -l T .env", false},
		{"rg passthru content", "rg --passthru T .env", true},
		{"rg passthru quiet pattern file", "rg --passthru -q -f .env README.md", true},
		{"rg passthru names pattern file", "rg -l --passthru -f .env README.md", true},
		{"rg passthru preprocessor", "rg -l --passthru --pre cat T .env", true},
		{"rg json passthru count", "rg --json --passthru -c T .env", true},
		{"rg mixed brace secret", "rg -g '{!*.md,*.secret}' T", true},
		{"rg mixed brace secret reversed", "rg -g '{*.secret,!*.md}' T", true},
		{"rg mixed iglob secret", "rg --iglob '{!*.md,*.secret}' T", true},
		{"rg positive secret", "rg -g '*.secret' T", true},
		{"rg protective config", "rg T", false},
		{"rg negative selector", "rg -g '!*.md' T", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, configPath := range []string{"", config} {
				// The two config-certification controls need the protective config.
				if configPath == "" && (tc.name == "rg protective config" || tc.name == "rg negative selector") {
					continue
				}
				t.Setenv("RIPGREP_CONFIG_PATH", configPath)
				for route, reason := range map[string]string{
					"source":     Analyze(tc.source, work, home, check),
					"shell argv": AnalyzeArgv([]string{"bash", "-c", tc.source}, work, home, check),
				} {
					deny := tc.deny
					if route == "shell argv" && (tc.name == "rg protective config" || tc.name == "rg negative selector") {
						// Nested shells cannot inherit config certification.
						deny = true
					}
					if (reason != "") != deny {
						t.Errorf("%s config=%t denial=%q want deny=%v", route, configPath != "", reason, deny)
					}
				}
			}
		})
	}
}
