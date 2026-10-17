package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// Advance a synthetic clock for every metadata proof instead of sleeping. The
// uncached Windows path costs exhaust the real two-second policy budget after
// 100 calls; repeated literals must reuse the proof, not need a larger budget.
func TestAudit24SlowLiteralResolution(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, code := range []string{strings.Repeat("x='a'\n", 256), strings.Repeat("print('a', 1)\n", 128)} {
		for _, shape := range []string{"inline", "heredoc", "here-string", "pipe", "argv"} {
			t.Run(shape+"/"+strings.SplitN(code, "\n", 2)[0], func(t *testing.T) {
				now := time.Now()
				start := now
				calls := make(map[[6]string]int)
				a := &analyzer{home: home, cwd: work, protected: cachedProtection(check),
					deadline: now.Add(2 * time.Second), now: func() time.Time { return now }}
				a.configWriteCheck = func(name, cwd, workdir, home, xdg, global string) bool {
					calls[[6]string{name, cwd, workdir, home, xdg, global}]++
					now = now.Add(20 * time.Millisecond)
					return paths.ConfigWriteProtected(name, cwd, workdir, home, xdg, global)
				}
				source := "python3 -c " + shellLiteral(code)
				switch shape {
				case "heredoc":
					source = "python3 <<'SYNTHETIC'\n" + code + "\nSYNTHETIC"
				case "here-string":
					source = "python3 <<< " + shellLiteral(code)
				case "pipe":
					source = "printf '%s' " + shellLiteral(code) + " | python3"
				}
				if shape == "argv" {
					a.command([]string{"python3", "-c", code}, 0, work, false)
				} else {
					a.fragment(source, 0)
				}
				if reason := a.decision(source); reason != "" {
					t.Fatalf("reason=%q after %v simulated metadata work", reason, now.Sub(start))
				}
				if len(calls) == 0 || now.Sub(start) >= 200*time.Millisecond {
					t.Errorf("metadata proofs=%d, simulated work=%v; want well below the policy deadline", len(calls), now.Sub(start))
				}
				t.Logf("metadata proofs=%d, simulated work=%v", len(calls), now.Sub(start))
				for key, count := range calls {
					if count != 1 {
						t.Errorf("metadata proof %q repeated %d times", key, count)
					}
				}
			})
		}
	}
}

func TestAudit24LiteralResolutionCacheScope(t *testing.T) {
	home, work, check := audit21Fixture(t)
	calls := 0
	a := &analyzer{home: home, cwd: work, protected: cachedProtection(check)}
	a.configWriteCheck = func(name, cwd, workdir, home, xdg, global string) bool {
		calls++
		// The path classifier reports lookup failures as protected. A cached
		// failure must remain a denial, just like a positive name witness.
		return name == "lookup-error" || paths.ConfigWriteProtected(name, cwd, workdir, home, xdg, global)
	}
	for i := 0; i < 3; i++ {
		child := a.literalChild(work)
		if child.metadata != a.pathMetadata() {
			t.Fatal("literal child has a private metadata snapshot")
		}
		if child.configPath("public", work) || !child.configPath("lookup-error", work) {
			t.Fatal("cached public or lookup-error result changed")
		}
	}
	if calls != 2 {
		t.Fatalf("path proofs=%d, want 2 across sibling literals", calls)
	}
	child := a.literalChild(work)
	child.env = map[string]string{"GIT_CONFIG_GLOBAL": "public"}
	if !child.configPath("public", work) {
		t.Fatal("child assignment reused a public-path proof")
	}
	if a.literalChild(work).configPath("public", work) {
		t.Fatal("child assignment escaped into its sibling")
	}
	before := calls
	if a.literalChild(filepath.Join(work, "sub")).configPath("public", filepath.Join(work, "sub")) {
		t.Fatal("public path in a second cwd became protected")
	}
	if calls != before+1 {
		t.Fatal("different cwd reused a path proof")
	}
	fresh := &analyzer{home: home, cwd: work, configWriteCheck: a.configWriteCheck}
	before = calls
	if fresh.literalChild(work).configPath("public", work) || calls != before+1 {
		t.Fatal("path proof survived into a fresh analysis")
	}
}

func TestAudit24LiteralResolutionDeadlineReason(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, argv := range []bool{false, true} {
		now := time.Now()
		a := &analyzer{home: home, cwd: work, protected: cachedProtection(check),
			deadline: now.Add(2 * time.Second), now: func() time.Time { return now }}
		a.configWriteCheck = func(name, cwd, workdir, home, xdg, global string) bool {
			now = now.Add(3 * time.Second)
			return false
		}
		source := "python3 -c " + shellLiteral("x='a'\n")
		if argv {
			a.command([]string{"python3", "-c", "x='a'\n"}, 0, work, false)
		} else {
			a.fragment(source, 0)
		}
		if reason := a.decision(source); reason != roles.Indeterminate {
			t.Errorf("argv=%v: deadline reason=%q, want indeterminate", argv, reason)
		}
	}
}
