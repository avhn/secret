package policy

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// syntheticIndex contains only fabricated names and zeroed stat/object fields.
func syntheticIndex(version uint32, names ...string) []byte {
	data := make([]byte, 12)
	copy(data, "DIRC")
	binary.BigEndian.PutUint32(data[4:], version)
	binary.BigEndian.PutUint32(data[8:], uint32(len(names)))
	previous := ""
	for _, name := range names {
		start := len(data)
		entry := make([]byte, 62)
		binary.BigEndian.PutUint16(entry[60:], uint16(len(name)))
		if version == 3 {
			entry[60] |= 0x40
			entry = append(entry, 0x40, 0)
		}
		data = append(data, entry...)
		suffix := name
		if version == 4 {
			common := 0
			for common < len(previous) && common < len(name) && previous[common] == name[common] {
				common++
			}
			strip := len(previous) - common
			encoded := []byte{byte(strip & 127)}
			for strip>>7 != 0 {
				strip = (strip >> 7) - 1
				encoded = append([]byte{byte(strip&127) | 128}, encoded...)
			}
			data = append(data, encoded...)
			suffix = name[common:]
		}
		data = append(data, []byte(suffix)...)
		data = append(data, 0)
		if version != 4 {
			for (len(data)-start)%8 != 0 {
				data = append(data, 0)
			}
		}
		previous = name
	}
	return indexChecksum(data)
}

func indexChecksum(data []byte) []byte { sum := sha1.Sum(data); return append(data, sum[:]...) }

func syntheticRepo(t testing.TB, root string, version uint32, names ...string) string {
	t.Helper()
	dir := filepath.Join(root, ".git")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "HEAD"), []byte("ref: refs/heads/synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index"), syntheticIndex(version, names...), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIndexVersions(t *testing.T) {
	for _, version := range []uint32{2, 3, 4} {
		for _, tc := range []struct {
			name  string
			names []string
			deny  bool
		}{
			{"empty", nil, false},
			{"safe", []string{"README.md", "src/code.go", "src/more.go"}, false},
			{"protected", []string{"README.md", "app.env"}, true},
			{"nested", []string{"README.md", "sub/.secrets/store"}, true},
			{"prefix removal", []string{strings.Repeat("x", 200) + ".go", "safe.go"}, false},
			{"prefix protected", []string{"sub/code.go", "sub/.env"}, true},
		} {
			t.Run(fmt.Sprintf("v%d/%s", version, tc.name), func(t *testing.T) {
				if got := indexNamesProtected(syntheticIndex(version, tc.names...), t.TempDir()); got != tc.deny {
					t.Fatalf("deny=%v want %v", got, tc.deny)
				}
			})
		}
	}
}

func TestIndexMalformed(t *testing.T) {
	valid := syntheticIndex(2, "safe.go")
	cases := map[string][]byte{
		"empty": nil, "signature": bytes.Repeat([]byte{0}, 32), "version": syntheticIndex(5, "safe.go"),
		"checksum": append([]byte(nil), valid...), "oversized": make([]byte, maxIndexBytes+1),
		"parent": syntheticIndex(2, "../safe.go"), "absolute": syntheticIndex(2, "/safe.go"),
		"windows separator": syntheticIndex(2, `sub\safe.go`),
	}
	cases["checksum"][len(valid)-1] ^= 1
	for _, extension := range []string{"link", "sdir", "FAIL"} {
		data := append([]byte(nil), valid[:len(valid)-20]...)
		data = append(data, []byte(extension)...)
		data = append(data, 0, 0, 0, 1)
		// Missing extension payload is malformed, even for optional extensions.
		cases[extension] = indexChecksum(data)
	}
	count := append([]byte(nil), valid[:len(valid)-20]...)
	binary.BigEndian.PutUint32(count[8:], maxIndexEntries+1)
	cases["count"] = indexChecksum(count)
	compressed := syntheticIndex(4, "safe.go")
	compressed = append([]byte(nil), compressed[:len(compressed)-20]...)
	compressed[74] = 127
	cases["v4 strip"] = indexChecksum(compressed)
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if !indexNamesProtected(data, t.TempDir()) {
				t.Fatal("malformed index allowed")
			}
		})
	}
	// Every truncation of an otherwise valid index must deny without a panic.
	for n := 0; n < len(valid); n++ {
		if !indexNamesProtected(valid[:n], t.TempDir()) {
			t.Fatalf("truncation %d allowed", n)
		}
	}
	// Optional extension bytes are bounded metadata and do not carry entry names.
	data := append([]byte(nil), valid[:len(valid)-20]...)
	data = append(data, []byte{'T', 'E', 'S', 'T', 0, 0, 0, 1, 0}...)
	if indexNamesProtected(indexChecksum(data), t.TempDir()) {
		t.Fatal("valid optional extension denied")
	}
}

func TestRepositoryMetadataFailures(t *testing.T) {
	root := t.TempDir()
	dir := syntheticRepo(t, root, 2, "safe.go")
	if indexProtected(dir, root) {
		t.Fatal("safe repository denied")
	}
	if err := os.Remove(filepath.Join(dir, "index")); err != nil {
		t.Fatal(err)
	}
	if indexProtected(dir, root) {
		t.Fatal("initialized empty repository denied")
	}
	if err := os.Mkdir(filepath.Join(dir, "index"), 0700); err != nil {
		t.Fatal(err)
	}
	if !indexProtected(dir, root) {
		t.Fatal("directory index allowed")
	}
	if !indexProtected(filepath.Join(root, "missing"), root) {
		t.Fatal("unresolved repository allowed")
	}
	if !indexProtected("", root) {
		t.Fatal("empty repository location allowed")
	}
	worktree := filepath.Join(root, "worktree")
	if err := os.Mkdir(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: ../.git\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := resolveGitDirectory(worktree, ""); !samePath(got, dir) {
		t.Fatalf("gitfile resolved to %q", got)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if resolveGitDirectory(worktree, "") != "" {
		t.Fatal("invalid gitfile resolved")
	}
}

func BenchmarkIndexNames(b *testing.B) {
	names := make([]string, 10000)
	for i := range names {
		names[i] = fmt.Sprintf("src/file-%05d.go", i)
	}
	data := syntheticIndex(4, names...)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		if indexNamesProtected(data, "") {
			b.Fatal("safe names denied")
		}
	}
}

func FuzzIndexNames(f *testing.F) {
	for _, v := range []uint32{2, 3, 4} {
		f.Add(syntheticIndex(v, "safe.go", "app.env"))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		indexNamesProtected(data, "")
		if len(data) >= 32 && len(data) <= maxIndexBytes {
			body := append([]byte(nil), data[:len(data)-20]...)
			indexNamesProtected(indexChecksum(body), "")
		}
	})
}

func TestGitRepositoryResolution(t *testing.T) {
	root := t.TempDir()
	tracked := filepath.Join(root, "tracked")
	dir := syntheticRepo(t, tracked, 4, ".env", "safe.go")
	clean := filepath.Join(root, "clean")
	syntheticRepo(t, clean, 2, "safe.go")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, args := range [][]string{
		{"git", "-C", tracked, "log", "-p"},
		{"git", "-C", dir, "--bare", "log", "-p"},
		{"git", "--git-dir", dir, "log", "-p"},
		{"git", "--git-dir=" + dir, "log", "-p"},
		{"git", "--git-dir=.git", "-C", tracked, "log", "-p"},
		{"git", "--work-tree", tracked, "log", "-p"},
		{"git", "--git-dir", dir, "--work-tree", clean, "log", "-p"},
		{"git", "--namespace", "demo", "--attr-source", "HEAD", "-C", tracked, "show", "HEAD"},
		{"git", "--git-dir", filepath.Join(root, "missing"), "log", "-p"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if AnalyzeArgv(args, clean, root, check) == "" {
				t.Fatal("protected or unresolved repository allowed")
			}
		})
	}
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE"} {
		t.Run(key, func(t *testing.T) {
			value := tracked
			if key == "GIT_DIR" {
				value = dir
			}
			t.Setenv(key, value)
			if AnalyzeArgv([]string{"git", "log", "-p"}, clean, root, check) == "" {
				t.Fatal("inherited repository location ignored")
			}
		})
	}
	for _, key := range []string{"GIT_EDITOR", "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "cat '"+filepath.ToSlash(filepath.Join(tracked, ".env"))+"'")
			if AnalyzeArgv([]string{"git", "status"}, clean, root, check) == "" {
				t.Fatal("inherited executable override ignored")
			}
		})
	}
	t.Run("oversized on disk", func(t *testing.T) {
		if err := os.Truncate(filepath.Join(dir, "index"), maxIndexBytes+1); err != nil {
			t.Fatal(err)
		}
		if !indexProtected(dir, root) {
			t.Fatal("oversized index allowed")
		}
	})
}

// samePath compares through symlinks, since macOS temp directories live under /private.
func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}
