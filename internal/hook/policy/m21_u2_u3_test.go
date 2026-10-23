package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Source strings are analyzer input only; no coprocess, reader or patch is run.
func TestM21U2CoprocFraming(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, keyword := range []string{"then", "elif", "else", "fi", "do", "done", "esac", "in", "select", "!", "}", "]]"} {
		for _, tail := range []string{" echo public", " >public.out", " { true; }", " echo public | cat"} {
			source := "coproc " + keyword + tail
			for _, code := range []string{source, "if false; then " + source + "; fi", "echo $(" + source + ")", strings.Replace(source, "coproc ", "coproc 2>public.out ", 1)} {
				if reason := Analyze(code, work, home, check); reason == "" {
					t.Errorf("malformed coprocess allowed: %q", code)
				}
				if reason := AnalyzeArgv([]string{"bash", "-c", code}, work, home, check); reason == "" {
					t.Errorf("malformed argv coprocess allowed: %q", code)
				}
			}
		}
		for _, quoted := range []string{shellLiteral(keyword), "\\" + keyword} {
			if reason := Analyze("coproc "+quoted+" public >public.out", work, home, check); reason != "" {
				t.Errorf("quoted command name %q: %s", quoted, reason)
			}
		}
	}
	for _, source := range []string{
		"coproc function f { true; }", "coproc coproc true", "coproc X function f { true; }",
		"coproc X coproc true", "coproc X time true", "coproc X let 1", "coproc X export A=public",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("uncertified coprocess head allowed: %q", source)
		}
	}
	for _, source := range []string{
		"coproc true", "coproc true >public.out", "coproc 'true' >public.out", "coproc \\true >public.out",
		"coproc { true; }", "coproc SYNTHETIC { true; }", "coproc 'then' { true; }", "coproc bad-name { true; }",
		"coproc SYNTHETIC ( true )", "coproc SYNTHETIC if true; then true; fi",
		"coproc SYNTHETIC { true; } | cat", "coproc SYNTHETIC ( true ) | cat",
		"coproc >public.out true", "coproc 2>public.out true", "coproc 1>&1 true", "coproc 2 >public.out true",
		"coproc SYNTHETIC for x in public; do echo public; done", "coproc SYNTHETIC [[ public == public ]]",
		"coproc { coproc true; }", "coproc time echo public", "coproc let 1", "coproc export A=public",
		"echo coproc then fi", "printf '%s' 'coproc then cat .env'",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public coprocess control %q: %s", source, reason)
		}
	}
}

func TestM21U3CoprocPhysicalPatchTarget(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(work, ".env"), filepath.Join(work, "public-link.txt")); err != nil {
		t.Skipf("synthetic symlink unavailable: %v", err)
	}
	for _, prefix := range []string{"coproc ", "coproc 2>public.out ", "coproc 3< public.patch "} {
		source := prefix + "apply_patch <<'PATCH'\n*** Begin Patch\n*** Update File: public-link.txt\n@@\n-old\n+synthetic\n*** End Patch\nPATCH"
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("protected physical patch target allowed: %q", source)
		}
		if reason := AnalyzeArgv([]string{"bash", "-c", source}, work, home, check); reason == "" {
			t.Errorf("argv protected physical patch target allowed: %q", source)
		}
	}
}

func TestM21U3PatchRecipients(t *testing.T) {
	home, work, check := audit21Fixture(t)
	public := "*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\n"
	protected := strings.Replace(public, "public.txt", ".env", 1)
	for _, prefix := range []string{"", "env ", "timeout 5 ", "command -p ", "coproc ", "coproc 2>public.out ", "coproc 00< public.patch ", "coproc 3< public.patch "} {
		for _, tc := range []struct {
			name, source string
			deny         bool
		}{
			{"public_heredoc", "apply_patch <<'PATCH'\n" + public + "PATCH", false},
			{"protected_heredoc", "apply_patch <<'PATCH'\n" + protected + "PATCH", true},
			{"malformed_heredoc", "apply_patch <<'PATCH'\nnot a patch\nPATCH", true},
			{"recipient_pipeline", "apply_patch <<'PATCH' | cat\nnot a patch\nPATCH", true},
			{"pipeline", "cat public.patch | apply_patch", true},
			{"pipeline_nonstdin", "cat public.patch | apply_patch 3<<'PATCH'\n" + public + "PATCH", true},
			{"process_stdin", "apply_patch < <(cat public.patch)", true},
			{"process_operand", "apply_patch <(cat public.patch) <<'PATCH'\n" + public + "PATCH", true},
			{"argv_shadow", "apply_patch 'not a patch' <<'PATCH'\n" + public + "PATCH", true},
			{"file", "apply_patch < public.patch", true},
			{"here_string", "apply_patch <<< " + shellLiteral(public), true},
			{"heredoc_shadow", "cat public.patch | apply_patch <<'PATCH'\n" + public + "PATCH", false},
			{"fd_shadow", "apply_patch <<'PATCH' 0<&3\n" + public + "PATCH", true},
			{"patch_output_pipe", "cat public.patch | patch -o output.txt", true},
			{"patch_output_file", "patch -o output.txt < public.patch", true},
			{"patch_output_heredoc", "patch --output=output.txt <<'PATCH'\n--- public.txt\n+++ public.txt\n@@ -1 +1 @@\n-old\n+new\nPATCH", true},
			{"git_apply_pipe", "cat public.patch | git apply", true},
			{"git_apply_dashed", "cat public.patch | git-apply", true},
			{"git_apply_process", "git apply < <(cat public.patch)", true},
			{"git_apply_mutating_check", "cat public.patch | git apply --check --apply", true},
			{"git_apply_heredoc", "git apply <<'PATCH'\n" + public + "PATCH", true},
			{"git_apply_check", "cat public.patch | git apply --check", false},
			{"patch_version", "patch --version", false},
			{"public_printer", "printf '%s' 'apply_patch .env'", false},
		} {
			t.Run(prefix+tc.name, func(t *testing.T) {
				// Put the prefix on the recipient, not its producer.
				source := tc.source
				for _, recipient := range []string{"apply_patch", "patch", "git", "printf"} {
					if strings.HasPrefix(source, recipient+" ") || source == recipient || strings.Contains(source, "| "+recipient) {
						source = strings.Replace(source, recipient, prefix+recipient, 1)
						break
					}
				}
				for _, argv := range []bool{false, true} {
					var reason string
					if argv {
						reason = AnalyzeArgv([]string{"bash", "-c", source}, work, home, check)
					} else {
						reason = Analyze(source, work, home, check)
					}
					if (reason != "") != tc.deny {
						t.Errorf("argv=%v source=%q deny=%v reason=%q", argv, source, tc.deny, reason)
					}
				}
			})
		}
	}
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"{ apply_patch; } <<'PATCH'\n" + public + "PATCH", false},
		{"{ cat public.patch | apply_patch; } <<'PATCH'\n" + public + "PATCH", true},
		{"{ coproc { apply_patch; }; } <<'PATCH'\n" + public + "PATCH", true},
		{"coproc { apply_patch; } <<'PATCH'\n" + public + "PATCH", false},
		{"coproc 00<<'PATCH' apply_patch\n" + public + "PATCH", false},
		{"coproc 3<<'PATCH' apply_patch\n" + public + "PATCH", true},
		{"{ coproc true; apply_patch; } <<'PATCH'\n" + public + "PATCH", false},
		{"{ apply_patch; } < <(cat public.patch)", true},
		{"patch --help", false},
		{"patch -v", false},
		{"patch --version public.patch", true},
	} {
		if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
			t.Errorf("source=%q deny=%v reason=%q", tc.source, tc.deny, reason)
		}
	}
}
