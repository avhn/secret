package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/patch"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// All commands are analyzer data only, with path metadata under a disposable HOME.
func TestAudit29PatchExpansion(t *testing.T) {
	home, work, check := audit21Fixture(t)
	aliasErr := os.Symlink(filepath.Join(home, ".aws"), filepath.Join(work, "aws"))
	for _, prefix := range []string{"", "env ", "timeout 5 ", "env -C sub "} {
		for _, tc := range []struct {
			name, assignment, target, delimiter string
			deny, opaque, alias                 bool
		}{
			{"env", "P=.env; ", "$P", "PATCH", true, false, false},
			{"aws_alias", "P=aws/credentials; ", "$P", "PATCH", true, false, true},
			{"aws_file", "f=~/.aws/credentials; ", "$f", "PATCH", true, false, false},
			{"aws_directory", "d=~/.aws; ", "$d/credentials", "PATCH", true, false, false},
			{"ssh_file", "f=$HOME/.ssh/id_rsa; ", "$f", "PATCH", true, false, false},
			{"git_file", "P=.git/config; ", "$P", "PATCH", true, false, false},
			{"git_directory", "d=.git; ", "$d/config", "PATCH", true, false, false},
			{"unknown", "", "$UNKNOWN_DIR/credentials", "PATCH", true, true, false},
			{"command", "", "$(printf public.txt)", "PATCH", true, true, false},
			{"backtick", "", "`echo ~/.aws`/credentials", "PATCH", true, true, false},
			{"arithmetic", "", "$((1))/credentials", "PATCH", true, true, false},
			{"parameter_operator", "", "${UNKNOWN_DIR:-public.txt}", "PATCH", true, true, false},
			{"reassigned", "P=public.txt; P=another.txt; ", "$P", "PATCH", true, true, false},
			{"public", "P=public.txt; ", "$P", "PATCH", false, false, false},
			{"template", "P=.env.example; ", "$P", "PATCH", false, false, false},
			{"quoted", "P=.env; ", "$P", "'PATCH'", false, false, false},
			{"quoted_git", "P=.git/config; ", "$P", "'PATCH'", true, false, false},
			{"double_quoted_git", "P=.git/config; ", "$P", "\"PATCH\"", true, false, false},
			{"escaped_delimiter_git", "P=.git/config; ", "$P", "\\PATCH", true, false, false},
			{"quoted_git_directory", "P=.git; ", "${P}/config", "'PATCH'", true, false, false},
			{"quoted_git_neighbor", "P=.github/config; ", "$P", "'PATCH'", false, false, false},
			{"double_quoted", "P=.env; ", "$P", "\"PATCH\"", false, false, false},
			{"escaped_delimiter", "P=.env; ", "$P", "\\PATCH", false, false, false},
			{"quoted_command", "", "$(printf public.txt)", "'PATCH'", false, false, false},
			{"escaped_parameter", "P=.env; ", "\\$P", "PATCH", false, false, false},
		} {
			t.Run(prefix+tc.name, func(t *testing.T) {
				if tc.alias && aliasErr != nil {
					t.Skipf("symlink metadata unavailable: %v", aliasErr)
				}
				// Both possible wrapper directories get the same synthetic alias.
				if tc.alias && strings.Contains(prefix, "-C") {
					target := filepath.Join(work, "sub", "aws")
					if err := os.Symlink(filepath.Join(home, ".aws"), target); err != nil && !os.IsExist(err) {
						t.Skipf("symlink metadata unavailable: %v", err)
					}
				}
				body := "*** Begin Patch\n*** Delete File: " + tc.target + "\n*** End Patch\n"
				source := tc.assignment + prefix + "apply_patch <<" + tc.delimiter + "\n" + body + "PATCH"
				for _, argv := range []bool{false, true} {
					var reason string
					if argv {
						reason = AnalyzeArgv([]string{"bash", "-lc", source}, work, home, check)
					} else {
						reason = Analyze(source, work, home, check)
					}
					if (reason != "") != tc.deny || tc.opaque && reason != roles.Indeterminate {
						t.Errorf("argv=%v deny=%v opaque=%v reason=%q", argv, tc.deny, tc.opaque, reason)
					}
				}
			})
		}
	}
}

func TestAudit29PatchQuotedGitHeaders(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, target := range []string{".git/config", ".github/config", ".env"} {
		for _, delimiter := range []string{"'PATCH'", "\"PATCH\"", "\\PATCH"} {
			for _, section := range []string{
				"*** Add File: ${P}\n+synthetic\n",
				"*** Update File: ${P}\n@@\n-old\n+synthetic\n",
				"*** Delete File: ${P}\n",
				"*** Update File: public.txt\n*** Move to: ${P}\n@@\n-old\n+synthetic\n",
			} {
				source := "P=" + target + "; apply_patch <<" + delimiter + "\n*** Begin Patch\n" + section + "*** End Patch\nPATCH"
				for _, argv := range []bool{false, true} {
					var reason string
					if argv {
						reason = AnalyzeArgv([]string{"bash", "-lc", source}, work, home, check)
					} else {
						reason = Analyze(source, work, home, check)
					}
					if (reason != "") != (target == ".git/config") {
						t.Errorf("argv=%v quoted target %q delimiter %q section %q: %q", argv, target, delimiter, section, reason)
					}
				}
			}
		}
	}
	// Parameter-looking payload bytes remain literal, not Git-write headers.
	source := "P=.git/config; apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: public.txt\n+$P\n*** End Patch\nPATCH"
	if reason := Analyze(source, work, home, check); reason != "" {
		t.Errorf("literal quoted payload denied: %q", reason)
	}
}

func TestAudit29PatchEffectiveInput(t *testing.T) {
	home, work, check := audit21Fixture(t)
	public := "*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\n"
	for _, prefix := range []string{"", "env ", "timeout 5 "} {
		for _, source := range []string{
			"apply_patch <<'PATCH' <<< 'x'\n" + public + "PATCH",
			"p='x'; apply_patch <<'PATCH' <<<\"$p\"\n" + public + "PATCH",
			"apply_patch <<'PATCH' <<<\"$(cat p.patch)\"\n" + public + "PATCH",
			"{ printf '%s' malformed | apply_patch; } <<'PATCH'\n" + public + "PATCH",
		} {
			source = strings.Replace(source, "apply_patch", prefix+"apply_patch", 1)
			if reason := Analyze(source, work, home, check); reason != roles.Indeterminate {
				t.Errorf("effective input not rejected: %q: %q", source, reason)
			}
		}
	}
	for _, source := range []string{
		"P=.env; { apply_patch; } <<PATCH\n*** Begin Patch\n*** Delete File: $P\n*** End Patch\nPATCH",
		"P=.env; apply_patch <<ONE <<'TWO'\n*** Begin Patch\n*** Delete File: $P\n*** End Patch\nONE\n" + public + "TWO",
		"apply_patch <<PATCH\n*** Begin Patch\n*** Add File: public.txt\n+$(printf synthetic)\n*** End Patch\nPATCH",
		"P='not a patch'; apply_patch <<PATCH\n$P\nPATCH",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("expanded or malformed patch allowed: %q", source)
		}
	}
}

func TestAudit29PatchExpansionBoundsAndCwd(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		name, source string
		deny         bool
	}{
		{"static_framing", "P='*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch'; apply_patch <<PATCH\n$P\nPATCH", false},
		{"expanded_size", "P='" + strings.Repeat("x", 1000) + "'; apply_patch <<PATCH\n*** Begin Patch\n*** Add File: " + strings.Repeat("$P", 42) + "\n+synthetic\n*** End Patch\nPATCH", true},
		{"child_store_cwd", "env -C " + shellLiteral(filepath.Join(home, ".aws")) + " apply_patch <<PATCH\n*** Begin Patch\n*** Delete File: credentials\n*** End Patch\nPATCH", true},
		{"child_public_cwd", "env -C sub apply_patch <<PATCH\n*** Begin Patch\n*** Delete File: credentials\n*** End Patch\nPATCH", false},
		{"parent_pwd", "env -C sub apply_patch <<PATCH\n*** Begin Patch\n*** Delete File: $PWD/.git/config\n*** End Patch\nPATCH", true},
		{"quoted_payload", "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: public.txt\n+$(printf synthetic) $UNKNOWN `echo literal`\n*** End Patch\nPATCH", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("deny=%v reason=%q", tc.deny, reason)
			}
		})
	}
}

func TestAudit29InheritedGitWriteRoots(t *testing.T) {
	home, work, _ := audit21Fixture(t)
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR", "GIT_CONFIG_GLOBAL", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	root := filepath.Join(work, "legacy")
	for _, dir := range []string{"objects", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := audit29HeadSymlink("refs/heads/main", filepath.Join(root, "HEAD")); err != nil {
		t.Skipf("legacy symbolic HEAD unavailable: %v", err)
	}
	if err := os.Symlink(root, filepath.Join(work, "alias")); err != nil {
		t.Skipf("symlink metadata unavailable: %v", err)
	}
	body := func(name string) string {
		return "*** Begin Patch\n*** Add File: " + filepath.ToSlash(name) + "\n+synthetic\n*** End Patch\n"
	}
	// Classified tightening: Git validate_headref accepts an unborn refs/ link.
	if !paths.ConfigWriteProtected("legacy/config", work, "", home, "", "") || patch.Decision(body("legacy/config"), work, "", home) == "" {
		t.Fatal("undeclared legacy refs/ root allowed")
	}
	// A non-refs dangling link does not establish a Git signature. Use it for
	// inherited-root tests so their denials cannot borrow signature discovery.
	if err := os.Remove(filepath.Join(root, "HEAD")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("public/missing", filepath.Join(root, "HEAD")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"legacy/config", "alias/config"} {
		if paths.ConfigWriteProtected(target, work, "", home, "", "") || patch.Decision(body(target), work, "", home) != "" {
			t.Fatalf("undeclared non-refs root control denied: %s", target)
		}
	}
	// An inherited relative root is anchored at the effective tool workdir.
	t.Run("workdir", func(t *testing.T) {
		t.Setenv("GIT_DIR", "../legacy")
		if !paths.ConfigWriteProtected("../legacy/config", work, "sub", home, "", "") || patch.Decision(body("../legacy/config"), work, "sub", home) == "" {
			t.Error("relative workdir lost inherited root")
		}
		if paths.ConfigWriteProtected("public.txt", work, "sub", home, "", "") {
			t.Error("unrelated workdir write denied")
		}
	})
	t.Run("physical_parent", func(t *testing.T) {
		if err := os.Mkdir(filepath.Join(home, "sub"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(home, "sub"), filepath.Join(work, "parent-link")); err != nil {
			t.Skipf("symlink metadata unavailable: %v", err)
		}
		t.Setenv("GIT_COMMON_DIR", "parent-link/../legacy")
		for _, target := range []string{filepath.Join(home, "legacy", "config"), filepath.Join(root, "config")} {
			if !paths.ConfigWriteProtected(target, work, "", home, "", "") || patch.Decision(body(target), work, "", home) == "" {
				t.Errorf("lexical or physical inherited root lost: %s", target)
			}
		}
	})
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR"} {
		for _, declared := range []string{root, "legacy", "./legacy/../legacy/", "alias", "missing-root"} {
			t.Run(key+"/"+declared, func(t *testing.T) {
				t.Setenv(key, declared)
				targets := []string{"legacy/config", "alias/config", "legacy/new/config", "legacy"}
				if declared == "missing-root" {
					targets = []string{"missing-root/config", "missing-root/new/config", "missing-root"}
				}
				for _, target := range targets {
					// Every file-write tool and the patch dispatcher use this shared check.
					if !paths.ConfigWriteProtected(target, work, "", home, "", "") {
						t.Errorf("file write allowed: %s", target)
					}
					if reason := patch.Decision(body(target), work, "", home); reason == "" {
						t.Errorf("patch write allowed: %s", target)
					}
				}
				for _, target := range []string{"public.txt", "legacy-neighbor/config"} {
					if paths.ConfigWriteProtected(target, work, "", home, "", "") {
						t.Errorf("unrelated file write denied: %s", target)
					}
					if reason := patch.Decision(body(target), work, "", home); reason != "" {
						t.Errorf("unrelated patch denied: %s: %s", target, reason)
					}
				}
			})
		}
	}
}
