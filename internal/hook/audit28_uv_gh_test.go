package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Commands are submitted as synthetic hook envelopes, never executed.
func TestAudit28UVToolOptions(t *testing.T) {
	home, work := audit28ToolsFixture(t)
	t.Setenv("GH_CONFIG_DIR", "")
	aws := filepath.Join(home, ".aws")
	project := filepath.Join(work, "project")
	for _, dir := range []string{aws, project} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(aws, "credentials"), filepath.Join(work, "public.txt"), filepath.Join(project, "pyproject.toml")} {
		if err := os.WriteFile(file, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, launcher := range [][]string{{"uvx"}, {"uv", "tool", "run"}, {"uv", "run"}} {
		for _, tc := range []struct {
			name string
			args []string
			deny bool
		}{
			{"directory", []string{"--directory", aws, "cat", "credentials"}, true},
			{"directory_equal", []string{"--directory=" + aws, "head", "credentials"}, true},
			{"directory_public", []string{"--directory", work, "cat", "public.txt"}, false},
			{"directory_metadata", []string{"--directory", aws, "stat", "credentials"}, false},
			{"project", []string{"--project", filepath.Join(work, ".secrets"), "true"}, true},
			{"project_equal", []string{"--project=" + filepath.Join(work, ".secrets"), "true"}, true},
			{"project_public", []string{"--project", project, "cat", "public.txt"}, false},
			{"requirements", []string{"--with-requirements", filepath.Join(aws, "credentials"), "true"}, true},
			{"requirements_equal", []string{"--with-requirements=" + filepath.Join(aws, "credentials"), "true"}, true},
			{"env_file", []string{"--env-file", filepath.Join(work, ".env"), "true"}, true},
			{"env_file_equal", []string{"--env-file=" + filepath.Join(work, ".env"), "true"}, true},
			{"config", []string{"--config-file", filepath.Join(aws, "credentials"), "true"}, true},
			{"cache", []string{"--cache-dir=" + filepath.Join(work, ".secrets"), "true"}, true},
			{"editable", []string{"--with-editable", filepath.Join(work, ".secrets"), "true"}, true},
			{"requirements_child_cwd", []string{"--with-requirements", "credentials", "--directory", aws, "true"}, true},
			{"env_public", []string{"--env-file", "public.txt", "cat", "public.txt"}, false},
			{"child_printer", []string{"--directory", work, "printenv"}, true},
			{"separator", []string{"--directory", aws, "--", "cat", "credentials"}, true},
			{"missing_value", []string{"--directory"}, true},
			{"empty_value", []string{"--directory="}, true},
			{"help", []string{"--help"}, false},
			{"version", []string{"--version"}, false},
			{"missing_child", []string{"--directory", work}, true},
			{"unknown_option", []string{"--unknown", "true"}, true},
		} {
			t.Run(strings.Join(launcher, "_")+"/"+tc.name, func(t *testing.T) {
				argv := append(append([]string(nil), launcher...), tc.args...)
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": argv}, tc.deny)
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": audit26Shell(argv)}, tc.deny)
			})
		}
	}
	for _, argv := range [][]string{
		{"uv", "--directory", aws, "tool", "run", "cat", "credentials"},
		{"uv", "tool", "--directory=" + aws, "run", "cat", "credentials"},
		{"uvx", "--from", "synthetic-package", "--directory", aws, "cat", "credentials"},
		{"uvx", "--from=python-dotenv", "dotenv", "list"},
	} {
		audit28ToolCheck(t, "Bash", work, map[string]any{"command": argv}, true)
		audit28ToolCheck(t, "Bash", work, map[string]any{"command": "env " + audit26Shell(argv)}, true)
	}
	// Directory state belongs to the child, not subsequent sibling commands.
	audit28ToolCheck(t, "Bash", work, map[string]any{"command": "uvx --directory " + audit26Shell([]string{aws}) + " true; cat public.txt"}, false)
	t.Run("project_alias", func(t *testing.T) {
		if err := os.Remove(filepath.Join(project, "pyproject.toml")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(aws, "credentials"), filepath.Join(project, "pyproject.toml")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		for _, launcher := range [][]string{{"uvx"}, {"uv", "tool", "run"}, {"uv", "run"}} {
			for _, option := range []string{"--project", "--directory", "--with-editable"} {
				argv := append(append([]string(nil), launcher...), option, project, "true")
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": argv}, true)
			}
		}
	})
}

func TestAudit28RelocatedGHHosts(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	t.Setenv("GH_CONFIG_DIR", "")
	for _, key := range []string{"XDG_CONFIG_HOME", "GH_CONFIG_DIR"} {
		t.Run(key, func(t *testing.T) {
			dir := filepath.Join(work, "custom")
			hosts := filepath.Join(dir, "hosts.yml")
			if key == "XDG_CONFIG_HOME" {
				hosts = filepath.Join(dir, "gh", "hosts.yml")
			}
			if err := os.MkdirAll(filepath.Dir(hosts), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hosts, []byte("synthetic\n"), 0600); err != nil {
				t.Fatal(err)
			}
			for _, prefix := range []string{key + "=" + audit26Shell([]string{dir}) + " ", "export " + key + "=" + audit26Shell([]string{dir}) + "; ", "env " + key + "=" + audit26Shell([]string{dir}) + " "} {
				for _, tc := range []struct {
					argv []string
					deny bool
				}{
					{[]string{"cat", hosts}, true}, {[]string{"rg", "synthetic", hosts}, true},
					{[]string{"rg", "-l", "synthetic", hosts}, true},
					{[]string{"gh", "auth", "token"}, true},
					{[]string{"gh", "auth", "status", "--show-token"}, true},
					{[]string{"gh", "config", "get", "oauth_token"}, true},
					{[]string{"cat", filepath.Join(dir, "public.yml")}, false},
					{[]string{"stat", hosts}, false}, {[]string{"gh", "auth", "status"}, false},
				} {
					t.Run(prefix+strings.Join(tc.argv, "_"), func(t *testing.T) {
						audit28ToolCheck(t, "Bash", work, map[string]any{"command": prefix + audit26Shell(tc.argv)}, tc.deny)
					})
				}
			}
			for _, reader := range [][]string{{"cat", hosts}, {"rg", "synthetic", hosts}} {
				argv := append([]string{"env", key + "=" + dir}, reader...)
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": argv}, true)
			}
			// Inherited relocation applies to native file tools and shell reads.
			t.Setenv(key, dir)
			for _, tool := range []string{"Read", "Write", "Edit"} {
				audit28ToolCheck(t, tool, work, map[string]any{"file_path": hosts}, true)
				audit28ToolCheck(t, tool, work, map[string]any{"file_path": filepath.Join(dir, "public.yml")}, false)
			}
			audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "synthetic", "path": filepath.Dir(hosts), "output_mode": "content"}, true)
			audit28ToolCheck(t, "Bash", work, map[string]any{"command": []string{"cat", hosts}}, true)
		})
	}
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{"export GH_CONFIG_DIR=custom; cat custom/hosts.yml", true},
		{"command export GH_CONFIG_DIR=custom; cat custom/hosts.yml", true},
		{"GH_CONFIG_DIR=custom cat < custom/hosts.yml", true},
		{"GH_CONFIG_DIR=custom; cat custom/hosts.yml", true},
		{"D=custom; export GH_CONFIG_DIR=$D; cat custom/hosts.yml", true},
		{"export GH_CONFIG_DIR=custom; gh auth token | secret stash synthetic TOKEN", false},
		{"export GH_CONFIG_DIR=custom; env GH_CONFIG_DIR=other true; cat custom/hosts.yml", true},
		{"if true; then export GH_CONFIG_DIR=custom; else export GH_CONFIG_DIR=other; fi; cat custom/hosts.yml", true},
		{"if true; then export GH_CONFIG_DIR=custom; else export GH_CONFIG_DIR=other; fi; cat other/hosts.yml", true},
		{"env GH_CONFIG_DIR=custom bash -c 'cat custom/hosts.yml'", true},
		{"env GH_CONFIG_DIR=custom cat custom/public.yml; cat custom/hosts.yml", false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			audit28ToolCheck(t, "Bash", work, map[string]any{"command": tc.command}, tc.deny)
		})
	}
	// Child-local assignments cannot protect unrelated sibling reads.
	for _, prefix := range []string{"env GH_CONFIG_DIR=custom ", "GH_CONFIG_DIR=custom ", "(export GH_CONFIG_DIR=custom; "} {
		command := prefix + "true"
		if strings.HasPrefix(prefix, "(") {
			command += ")"
		}
		audit28ToolCheck(t, "Bash", work, map[string]any{"command": command + "; cat custom/hosts.yml"}, false)
	}
}
