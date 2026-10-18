package policy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// Charge slow-runner metadata costs without sleeping. Repeated joins used to
// resolve the same cwd more than twenty times and exhaust the two-second budget.
func TestSlowConditionalCWDResolution(t *testing.T) {
	home, work, check := audit21Fixture(t)
	work, err := filepath.EvalSymlinks(work)
	if err != nil {
		t.Fatal(err)
	}
	target := "first" + string(os.PathListSeparator) + "second"
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, name := range []string{target, "first", "second", "other", "README.md"} {
			t.Run(key+"/"+name, func(t *testing.T) {
				now := time.Now()
				start := now
				calls := 0
				a := &analyzer{home: home, cwd: work, protected: cachedProtection(check),
					deadline: now.Add(2 * time.Second), now: func() time.Time { return now }}
				a.cwdPathCheck = func(dir string) (string, error) {
					calls++
					now = now.Add(100 * time.Millisecond)
					return filepath.EvalSymlinks(dir)
				}
				source := "if true; then export " + key + "=" + shellLiteral(target) + "; else export " + key + "=other; fi; cat " + shellLiteral(name)
				a.fragment(source, 0)
				if reason := a.decision(source); (reason != "") != (name == target || name == "other") {
					t.Fatalf("reason=%q after %v simulated cwd resolution", reason, now.Sub(start))
				}
				if calls != 1 || now.Sub(start) != 100*time.Millisecond {
					t.Errorf("cwd resolutions=%d, simulated work=%v; want one 100ms proof", calls, now.Sub(start))
				}
			})
		}
	}
}

func TestCWDResolutionCacheScope(t *testing.T) {
	home, work, _ := audit21Fixture(t)
	alias := filepath.Join(work, "alias")
	// Keep the unclean spelling: cleaning before lookup loses the link's parent.
	rawParent := alias + string(os.PathSeparator) + ".."
	missing := filepath.Join(work, "missing")
	denied := filepath.Join(work, "denied")
	calls := make(map[string]int)
	check := func(dir string) (string, error) {
		calls[dir]++
		switch dir {
		case alias:
			return home, nil
		case rawParent:
			return filepath.Dir(home), nil
		case missing:
			return "", os.ErrNotExist
		case denied:
			return "", os.ErrPermission
		default:
			return dir, nil
		}
	}
	a := &analyzer{cwdPathCheck: check}
	for i := 0; i < 3; i++ {
		child := a.literalChild(work)
		got := child.cwdUnion([]string{alias, home, rawParent, missing, denied, ""})
		want := []string{home, filepath.Dir(home), missing, denied, ""}
		if !slices.Equal(got, want) {
			t.Fatalf("joined cwd=%q, want %q", got, want)
		}
	}
	if len(calls) != 5 {
		t.Fatalf("cwd proofs=%d, want 5 distinct raw paths", len(calls))
	}
	for dir, count := range calls {
		if count != 1 {
			t.Errorf("cwd proof %q repeated %d times", dir, count)
		}
	}
	fresh := &analyzer{cwdPathCheck: check}
	if fresh.canonicalCWD(alias) != home || calls[alias] != 2 {
		t.Fatal("cwd proof survived into a fresh analysis")
	}
}
