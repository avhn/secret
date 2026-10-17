package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type corpusFixtureKey struct {
	snapshot int
	extra    string
}

// Analysis only reads fixture metadata. Reuse each immutable snapshot within one
// corpus run, but isolate the cases that add a visible protected search input.
// The parent test owns cleanup so a subtest cannot remove a later case's tree.
type corpusFixtures struct {
	root        string
	repository  string
	snapshots   [][][3]string
	directories map[corpusFixtureKey]string
}

func (f *corpusFixtures) directory(t *testing.T, snapshot int, extra string) string {
	t.Helper()
	fixtures := f.snapshots[snapshot]
	if unsupportedCorpusFixtures(fixtures, runtime.GOOS) {
		// Preserve the existing Windows skips before creating a partial tree.
		t.Skip("fixture name is not valid on Windows")
	}
	key := corpusFixtureKey{snapshot, extra}
	if dir := f.directories[key]; dir != "" {
		return dir
	}
	dir, err := os.MkdirTemp(f.root, "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCorpusFixtures(dir, f.repository, fixtures); err != nil {
		t.Fatal(err)
	}
	if extra != "" {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(extra)), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if f.directories == nil {
		f.directories = make(map[corpusFixtureKey]string)
	}
	f.directories[key] = dir
	return dir
}

func unsupportedCorpusFixtures(fixtures [][3]string, goos string) bool {
	if goos == "windows" {
		for _, fixture := range fixtures {
			if strings.ContainsAny(fixture[0], "\n\r:*?\"<>|") {
				return true
			}
		}
	}
	return false
}

func writeCorpusFixtures(dir, repository string, fixtures [][3]string) error {
	replace := strings.NewReplacer("@TMP@", filepath.ToSlash(dir), "@ROOT@", filepath.ToSlash(repository))
	for _, fixture := range fixtures {
		name := filepath.Join(dir, filepath.FromSlash(fixture[0]))
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			return err
		}
		var err error
		switch fixture[1] {
		case "dir":
			err = os.MkdirAll(name, 0700)
		case "unreadable-dir":
			err = os.MkdirAll(name, 0000)
		case "unreadable":
			err = os.WriteFile(name, nil, 0000)
		case "link":
			err = os.Symlink(replace.Replace(fixture[2]), name)
		case "file":
			err = os.WriteFile(name, []byte(replace.Replace(fixture[2])), 0600)
		default:
			err = fmt.Errorf("unknown synthetic fixture kind %q", fixture[1])
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func TestCorpusFixturesReuseAndIsolation(t *testing.T) {
	fixtures := corpusFixtures{
		root:       t.TempDir(),
		repository: t.TempDir(),
		snapshots: [][][3]string{
			{{"search/sub", "dir", ""}, {"config", "file", "@TMP@/search @ROOT@/examples"}},
			{{"other", "file", ""}},
		},
	}
	var first string
	t.Run("initial owner", func(t *testing.T) {
		first = fixtures.directory(t, 0, "")
	})
	t.Run("reuse after subtest cleanup", func(t *testing.T) {
		if got := fixtures.directory(t, 0, ""); got != first {
			t.Fatalf("snapshot rebuilt: %q != %q", got, first)
		}
		data, err := os.ReadFile(filepath.Join(first, "config"))
		if err != nil || string(data) != filepath.ToSlash(first)+"/search "+filepath.ToSlash(fixtures.repository)+"/examples" {
			t.Fatalf("snapshot content or lifetime changed: %q, %v", data, err)
		}
	})
	for _, extra := range []string{"search/sub/app.env", "search/app.env"} {
		modified := fixtures.directory(t, 0, extra)
		if modified == first || fixtures.directory(t, 0, extra) != modified {
			t.Fatal("case-specific fixture was not isolated and reused")
		}
		if _, err := os.Stat(filepath.Join(modified, filepath.FromSlash(extra))); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(first, filepath.FromSlash(extra))); !os.IsNotExist(err) {
			t.Fatalf("case-specific input leaked into shared snapshot: %v", err)
		}
	}
	if fixtures.directory(t, 1, "") == first {
		t.Fatal("different snapshots share a directory")
	}
	entries, err := os.ReadDir(fixtures.root)
	if err != nil || len(entries) != 4 {
		t.Fatalf("expected exactly one tree per snapshot and overlay: %d, %v", len(entries), err)
	}
}

func TestCorpusFixturesPlatformPreflight(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, name := range []string{"ordinary/path", "line\nbreak", "line\rbreak", "drive:colon", "star*", "question?", `quote"`, "less<", "greater>", "pipe|"} {
			fixtures := [][3]string{{"ordinary", "dir", ""}, {name, "file", ""}}
			want := goos == "windows" && name != "ordinary/path"
			if got := unsupportedCorpusFixtures(fixtures, goos); got != want {
				t.Errorf("%s %q: unsupported=%v, want %v", goos, name, got, want)
			}
		}
	}
}
