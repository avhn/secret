package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/roles"
)

// Candidate commands are analyzer input only. All path metadata is disposable.
func TestReviewA3b0306PatchStdin(t *testing.T) {
	home, work, check := audit21Fixture(t)
	aliasErr := os.Symlink(filepath.Join(home, ".aws"), filepath.Join(work, "review_cfg"))
	public := "*** Begin Patch\n*** Add File: public.txt\n+synthetic\n*** End Patch\n"
	protected := "*** Begin Patch\n*** Update File: review_cfg/credentials\n@@\n-old\n+synthetic\n*** End Patch\n"
	if err := os.WriteFile(filepath.Join(work, "p.patch"), []byte(protected), 0600); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"", "env ", "env -i ", "timeout 5 ", "nice "} {
		for _, tc := range []struct {
			name, source string
			deny, opaque bool
			alias        bool
		}{
			{"no_stdin", "apply_patch", true, true, false},
			{"pipe", "cat p.patch | apply_patch", true, true, false},
			{"file", "apply_patch < p.patch", true, true, false},
			{"fd3", "apply_patch 3<<'PATCH'\n" + public + "PATCH", true, true, false},
			{"pipe_fd3", "cat p.patch | apply_patch 3<<'PATCH'\n" + public + "PATCH", true, true, false},
			{"file_fd3", "apply_patch < p.patch 3<<'PATCH'\n" + public + "PATCH", true, true, false},
			{"heredoc_then_file", "apply_patch <<'PATCH' < p.patch\n" + public + "PATCH", true, true, false},
			{"leading_heredoc_then_file", "<<'PATCH' apply_patch < p.patch\n" + public + "PATCH", true, true, false},
			{"leading_public", "<<'PATCH' apply_patch\n" + public + "PATCH", false, false, false},
			{"leading_protected", "<<'PATCH' apply_patch\n" + protected + "PATCH", true, false, true},
			{"heredoc_then_dup", "apply_patch <<'PATCH' 0<&3\n" + public + "PATCH", true, true, false},
			{"heredoc_then_here_string", "apply_patch <<'PATCH' <<< 'not a patch'\n" + public + "PATCH", true, true, false},
			{"two_heredocs_protected", "apply_patch <<'ONE' <<'TWO'\n" + public + "ONE\n" + protected + "TWO", true, false, true},
			{"two_heredocs_malformed", "apply_patch <<'ONE' <<'TWO'\n" + public + "ONE\nnot a patch\nTWO", true, false, false},
			{"same_scope_prior_malformed", "apply_patch <<'ONE' <<'TWO'\nnot a patch\nONE\n" + public + "TWO", true, false, false},
			{"public", "apply_patch <<'PATCH'\n" + public + "PATCH", false, false, false},
			{"explicit_stdin", "apply_patch 0<<'PATCH'\n" + public + "PATCH", false, false, false},
			{"zero_padded_stdin", "apply_patch 00<<'PATCH'\n" + public + "PATCH", false, false, false},
			{"file_then_heredoc", "apply_patch < p.patch <<'PATCH'\n" + public + "PATCH", false, false, false},
			{"pipe_then_heredoc", "cat p.patch | apply_patch <<'PATCH'\n" + public + "PATCH", false, false, false},
			{"nonstdin_file", "apply_patch <<'PATCH' 3< p.patch\n" + public + "PATCH", false, false, false},
			{"nonstdin_protected_file", "apply_patch <<'PATCH' 3< ~/.aws/credentials\n" + public + "PATCH", true, false, false},
			{"protected_alias", "apply_patch <<'PATCH'\n" + protected + "PATCH", true, false, true},
		} {
			t.Run(prefix+tc.name, func(t *testing.T) {
				if tc.alias && aliasErr != nil {
					t.Skipf("symlink metadata unavailable: %v", aliasErr)
				}
				source := strings.Replace(tc.source, "apply_patch", prefix+"apply_patch", 1)
				reason := Analyze(source, work, home, check)
				if (reason != "") != tc.deny || tc.opaque && reason != roles.Indeterminate {
					t.Fatalf("deny=%v opaque=%v reason=%q", tc.deny, tc.opaque, reason)
				}
			})
		}
	}
	for _, source := range []string{
		"{ env apply_patch; } <<'PATCH'\n" + public + "PATCH",
		"{ cat p.patch | env apply_patch; } <<'PATCH'\n" + public + "PATCH",
		"{ env apply_patch < p.patch; } <<'PATCH'\n" + public + "PATCH",
		"{ env apply_patch <<'INNER'\n" + public + "INNER\n} <<'OUTER'\nnot a patch\nOUTER",
	} {
		deny := strings.Contains(source, "p.patch")
		if reason := Analyze(source, work, home, check); (reason != "") != deny {
			t.Errorf("group source %q: deny=%v reason=%q", source, deny, reason)
		}
	}
}

func TestReviewA3b0306BraceCaps(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, code := range []string{
		"cat " + strings.Repeat("{", 65) + "x" + strings.Repeat("}", 65) + " ~/.aws/credentials",
		"cat {" + strings.Repeat("public,", 65) + "~/.aws/credentials}",
		"cat " + strings.Repeat("{a,b}", 10) + "{public,~/.aws/credentials}",
		"cat " + strings.Repeat("{a,b}", 5) + strings.Repeat("x", 700) + " ~/.aws/credentials",
		"cat {" + strings.Repeat("{", 65) + "x" + strings.Repeat("}", 65) + ",~/.aws/credentials}",
	} {
		if reason := Analyze("curl "+shellLiteral(code), work, home, check); reason == "" {
			t.Errorf("capped executable argument allowed: %q", code)
		}
	}
	for _, source := range []string{"curl 'cat {a,b} README.md'", "printf %s '" + strings.Repeat("{", 65) + "public" + strings.Repeat("}", 65) + "'"} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public argument denied: %q: %s", source, reason)
		}
	}
}
