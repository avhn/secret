package hook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Submit candidate commands only as JSON. All paths and metadata are disposable,
// and no requested patch, search, interpreter or reader is executed.
func audit28ToolsFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{home, work} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "RIPGREP_CONFIG_PATH"} {
		t.Setenv(key, "")
	}
	return home, work
}

func audit28ToolCheck(t *testing.T, tool, cwd string, fields map[string]any, deny bool) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": cwd, "tool_input": fields})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"claude", "codex"} {
		var output bytes.Buffer
		if err := Decide(host, bytes.NewReader(payload), &output); err != nil {
			t.Fatal(err)
		}
		if output.Len() == 0 {
			if deny {
				t.Errorf("%s %s allowed, want deny", host, tool)
			}
			continue
		}
		var result struct {
			Hook struct {
				Decision string `json:"permissionDecision"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Hook.Decision != "deny" {
			t.Fatalf("%s invalid decision: %s", host, output.String())
		}
		if !deny {
			t.Errorf("%s %s denied, want allow: %s", host, tool, output.String())
		}
	}
}

func TestAudit28WrappedPatch(t *testing.T) {
	home, work := audit28ToolsFixture(t)
	valid := "*** Begin Patch\n*** Add File: public.txt\n+public\n*** End Patch\n"
	malformed := strings.TrimSuffix(valid, "*** End Patch\n")
	wrappers := []string{"", "env ", "env -i ", "env -S ", "env -Sapply_patch ", "timeout 5 ", "gtimeout -s TERM 5 ", "nice ", "nice -n 2 ", "stdbuf -oL ", "nohup ", "setsid ", "command -p ", "builtin ", "exec ", "ionice -c 3 ", "chrt 0 ", "taskset 0x1 ", "flock lockfile ", "unbuffer ", "caffeinate -i ", "systemd-run --user --pipe --wait ", "time ", "env -i timeout 5 nice "}
	for _, wrapper := range wrappers {
		for _, tc := range []struct {
			name, body string
			deny       bool
		}{{"valid", valid, false}, {"malformed", malformed, true}} {
			t.Run(wrapper+tc.name, func(t *testing.T) {
				command := wrapper + "apply_patch <<'PATCH'\n" + tc.body + "PATCH\n"
				// The existing launcher-stdin policy denies systemd-run even
				// with a valid public body. Keep that denial unchanged.
				deny := tc.deny || strings.HasPrefix(wrapper, "systemd-run ")
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, deny)
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": []string{"bash", "-c", command}}, deny)
			})
		}
		audit28ToolCheck(t, "Bash", work, map[string]any{"command": wrapper + "apply_patch"}, true)
	}
	for _, body := range []string{valid, malformed} {
		audit28ToolCheck(t, "apply_patch", work, map[string]any{"command": body}, body == malformed)
	}
	// A command query must not execute or validate its apparent child.
	audit28ToolCheck(t, "Bash", work, map[string]any{"command": "command -v apply_patch <<'PATCH'\npublic\nPATCH"}, false)
	// Valid framing does not exempt protected argument words from existing rules.
	audit28ToolCheck(t, "Bash", work, map[string]any{"command": "apply_patch .git/config <<'PATCH'\n" + valid + "PATCH"}, true)
	t.Run("symlink_targets", func(t *testing.T) {
		target := filepath.Join(home, ".aws")
		if err := os.MkdirAll(target, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(work, "cfg")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		for _, wrapper := range wrappers {
			for _, header := range []string{"*** Update File: cfg/credentials\n@@\n-old\n+new", "*** Delete File: cfg/credentials", "*** Update File: public.txt\n*** Move to: cfg/credentials\n@@\n-old\n+new"} {
				for _, ending := range []string{"", "*** End Patch\n"} {
					command := wrapper + "apply_patch <<'PATCH'\n*** Begin Patch\n" + header + "\n" + ending + "PATCH\n"
					audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, true)
					audit28ToolCheck(t, "Bash", work, map[string]any{"command": []string{"bash", "-c", command}}, true)
				}
			}
		}
		// The patch body belongs to the child cwd, not the envelope cwd.
		command := "env -C " + audit26Shell([]string{work}) + " apply_patch <<'PATCH'\n*** Begin Patch\n*** Delete File: cfg/credentials\n*** End Patch\nPATCH"
		audit28ToolCheck(t, "Bash", home, map[string]any{"command": command}, true)
		command = "(env apply_patch) <<'PATCH'\n*** Begin Patch\n*** Delete File: cfg/credentials\n*** End Patch\nPATCH"
		audit28ToolCheck(t, "Bash", work, map[string]any{"command": command}, true)
	})
}

func TestAudit28PatchRedirectScope(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	valid := "*** Begin Patch\n*** Add File: public.txt\n+public\n*** End Patch\n"
	malformed := strings.TrimSuffix(valid, "*** End Patch\n")
	for _, wrapper := range []string{"", "env ", "env -i ", "timeout 5 ", "nice "} {
		for _, tc := range []struct {
			name, command string
			deny          bool
		}{
			{"direct_valid", wrapper + "apply_patch <<'PATCH'\n" + valid + "PATCH\n", false},
			{"inherited_valid", "{ " + wrapper + "apply_patch; } <<'PATCH'\n" + valid + "PATCH\n", false},
			{"overridden_ancestor", "{ " + wrapper + "apply_patch <<'PATCH'\n" + valid + "PATCH\n} <<'OUTER'\npublic\nOUTER\n", false},
			{"overridden_subshell", "(" + wrapper + "apply_patch <<'PATCH'\n" + valid + "PATCH\n) <<'OUTER'\npublic\nOUTER\n", false},
			{"malformed_child", "{ " + wrapper + "apply_patch <<'PATCH'\n" + malformed + "PATCH\n} <<'OUTER'\n" + valid + "OUTER\n", true},
			{"malformed_ancestor", "{ " + wrapper + "apply_patch; } <<'PATCH'\n" + malformed + "PATCH\n", true},
			{"direct_multiple", wrapper + "apply_patch <<'FIRST' <<'PATCH'\npublic\nFIRST\n" + valid + "PATCH\n", true},
			{"stdout_inherits", "{ " + wrapper + "apply_patch >public.log; } <<'OUTER'\npublic\nOUTER\n", true},
			{"sibling_restores", "{ " + wrapper + "apply_patch <<'PATCH'\n" + valid + "PATCH\n" + wrapper + "apply_patch; } <<'OUTER'\npublic\nOUTER\n", true},
		} {
			t.Run(wrapper+tc.name, func(t *testing.T) {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": tc.command}, tc.deny)
			})
		}
	}
}

func TestAudit28GrepModesAndHosts(t *testing.T) {
	home, work := audit28ToolsFixture(t)
	aws := filepath.Join(home, ".aws")
	if err := os.MkdirAll(aws, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{filepath.Join(aws, "credentials"), filepath.Join(work, ".env")} {
		if err := os.WriteFile(name, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range []map[string]any{{"path": aws}, {}, {"glob": "**/.env"}, {"type": "env"}} {
		for _, mode := range []any{nil, "files_with_matches", "", "content", "count", " content", "CONTENT", true, []string{"content"}} {
			t.Run(fmt.Sprintf("%v/%v", scope, mode), func(t *testing.T) {
				fields := map[string]any{"pattern": "SYNTHETIC"}
				for key, value := range scope {
					fields[key] = value
				}
				if mode != nil {
					fields["output_mode"] = mode
				}
				names := mode == nil
				if value, ok := mode.(string); ok {
					names = value == "files_with_matches"
				}
				audit28ToolCheck(t, "Grep", work, fields, !names)
			})
		}
	}
	for _, name := range []string{filepath.Join(aws, "credentials"), filepath.Join(work, ".env")} {
		audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "path": name, "output_mode": "files_with_matches"}, true)
	}
	audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "output_mode": nil}, true)
	audit28ToolCheck(t, "Grep", home, map[string]any{"pattern": "public", "path": work, "glob": "*.ts", "output_mode": ""}, false)
	t.Run("alias", func(t *testing.T) {
		alias := filepath.Join(work, "alias.txt")
		if err := os.Symlink(filepath.Join(aws, "credentials"), alias); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "path": alias, "output_mode": ""}, true)
		audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "path": alias}, false)
	})
}

func TestAudit28GrepGlobLists(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	for _, name := range []string{".env", ".netrc", ".env.ts", "app.ts", "main.go", "src/README.md", ".aws/credentials"} {
		target := filepath.Join(work, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		glob string
		deny bool
	}{
		{".env,*.ts", true}, {"*.ts,**/credentials", true},
		{"*.ts .netrc", true}, {".env,*.{ts,tsx}", true},
		{"*.ts,!*.md", true}, {"!*.md,*.ts", true},
		{"*.go,*.md", false}, {"*.{go,md}", false},
		{"*.go   *.md", false}, {"src/**,*.go", false},
		{"*.{ts,tsx}", true}, {"{*.go,*.md} *.ts", true},
		{"*.go,", true}, {strings.Repeat("*.go,", 65) + "*.md", true},
	} {
		t.Run(tc.glob, func(t *testing.T) {
			audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "glob": tc.glob, "output_mode": "content"}, tc.deny)
		})
	}
	// Plain literal selectors retain their denial in names-only mode too.
	audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "glob": ".env,*.go"}, true)
	// Combined brace expansion has one budget even when each selector is safe.
	audit28ToolCheck(t, "Grep", filepath.Join(work, "src"), map[string]any{"pattern": "public", "glob": strings.TrimSpace(strings.Repeat("*.{go,md,rs} ", 22)), "output_mode": "content"}, true)
}

func TestAudit28GrepGlobOrderParity(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	if err := os.Mkdir(filepath.Join(work, "src"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "src", "main.go"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		glob string
		deny bool
	}{
		{"*.go,src/**", true},
		{"src/**,*.go", false},
		{"*.go,src/**,*.md", false},
		{"src/**,*.go,*.md", false},
	} {
		t.Run(tc.glob, func(t *testing.T) {
			audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "synthetic", "glob": tc.glob, "output_mode": "content"}, tc.deny)
			// The existing whole-selector check did not deny names-only calls.
			audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "synthetic", "glob": tc.glob, "output_mode": "files_with_matches"}, false)
		})
	}
}

func TestAudit28ConfiguredCaseTools(t *testing.T) {
	home, work := audit28ToolsFixture(t)
	for _, key := range []string{"KUBECONFIG", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"} {
		t.Run(key, func(t *testing.T) {
			target := filepath.Join(home, "custom", "profile.cfg")
			t.Setenv(key, target)
			for _, name := range []string{filepath.Join(home, "custom", "PROFILE.CFG"), filepath.Join(home, "Custom", "profile.cfg"), filepath.Join(home, "CUSTOM", "PROFILE.CFG")} {
				for _, tool := range []string{"Read", "Write", "Edit", "MultiEdit"} {
					audit28ToolCheck(t, tool, work, map[string]any{"file_path": name}, true)
				}
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": []string{"cat", name}}, true)
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": audit26Shell([]string{"cat", name})}, true)
				audit28ToolCheck(t, "Grep", work, map[string]any{"pattern": "SYNTHETIC", "path": name, "output_mode": "content"}, true)
			}
			audit28ToolCheck(t, "Read", work, map[string]any{"file_path": filepath.Join(home, "custom", "public.cfg")}, false)
		})
	}
}
