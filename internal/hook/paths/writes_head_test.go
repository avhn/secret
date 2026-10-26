package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestGitHeadSignatures(t *testing.T) {
	testGitHeadSignatures(t, false, func(t *testing.T, root, dir string, want bool) {
		t.Helper()
		if got := gitHeadSignature(filepath.Join(dir, "HEAD")); got != want {
			t.Errorf("HEAD signature = %v, want %v", got, want)
		}
		for _, name := range []string{"config", "hooks/new"} {
			if got := ConfigWriteProtected(filepath.Join(dir, filepath.FromSlash(name)), root, "", root, "", ""); got != want {
				t.Errorf("ConfigWriteProtected(%q) = %v, want %v", name, got, want)
			}
		}
	})
}

// Both the portable and native Windows discovery paths must apply the same
// HEAD rule, independently of objects/refs versus linked-worktree metadata.
func testGitHeadSignatures(t *testing.T, native bool, check func(*testing.T, string, string, bool)) {
	t.Helper()
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR", "GIT_CONFIG_GLOBAL", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	for _, metadata := range []string{"objects_refs", "commondir"} {
		for _, tc := range []struct {
			name, kind, target string
			want               bool
		}{
			{"regular", "file", "", true},
			{"regular_contents_unchanged", "empty", "", true},
			{"missing", "missing", "", false},
			{"directory", "directory", "", false},
			{"unborn_refs", "link", "refs/heads/main", true},
			{"refs_prefix_only", "link", "refs/", true},
			{"existing_refs", "existing_link", "refs/heads/main", true},
			{"dangling_non_refs", "link", "public/missing", false},
			{"existing_non_refs", "existing_link", "public/main", true},
			{"relative_refs", "link", "./refs/heads/main", false},
			{"refs_neighbor", "link", "refs-public/main", false},
			{"case_sensitive_prefix", "link", "REFS/heads/main", false},
			{"backslash_prefix", "link", `refs\heads\main`, false},
			{"link_loop", "link", "HEAD", false},
		} {
			t.Run(metadata+"/"+tc.name, func(t *testing.T) {
				root := t.TempDir()
				dir := filepath.Join(root, "metadata")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if metadata == "objects_refs" {
					for _, name := range []string{"objects", "refs"} {
						if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
							t.Fatal(err)
						}
					}
				} else if err := os.WriteFile(filepath.Join(dir, "commondir"), []byte("../common\n"), 0600); err != nil {
					t.Fatal(err)
				}
				head := filepath.Join(dir, "HEAD")
				switch tc.kind {
				case "file", "empty":
					var data []byte
					if tc.kind == "file" {
						data = []byte("ref: refs/heads/main\n")
					}
					if err := os.WriteFile(head, data, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(head, 0700); err != nil {
						t.Fatal(err)
					}
				case "link", "existing_link":
					if tc.kind == "existing_link" {
						target := filepath.Join(dir, filepath.FromSlash(tc.target))
						if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(target, []byte("synthetic\n"), 0600); err != nil {
							t.Fatal(err)
						}
					}
					if err := gitHeadSymlink(tc.target, head); err != nil {
						t.Skipf("symbolic HEAD unavailable: %v", err)
					}
					if text, err := os.Readlink(head); err != nil || text != tc.target {
						t.Fatalf("HEAD link text = %q, %v; want %q", text, err, tc.target)
					}
				}
				want := tc.want
				if native && tc.name == "link_loop" {
					// Native discovery keeps unresolvable existing HEADs fail-closed.
					want = true
				}
				check(t, root, dir, want)
			})
		}
	}
}

func TestGitHeadSignatureMetadataErrors(t *testing.T) {
	root := t.TempDir()
	head := filepath.Join(root, "HEAD")
	if err := gitHeadSymlink("refs/heads/main", head); err != nil {
		t.Skipf("symbolic HEAD unavailable: %v", err)
	}
	// Inject errors rather than depend on permissions (which root can bypass)
	// or races between lstat and readlink. Even partial refs/ text is not proof.
	for _, cause := range []error{fs.ErrNotExist, fs.ErrPermission, fs.ErrInvalid} {
		for _, stage := range []string{"lstat", "readlink"} {
			t.Run(stage+"/"+cause.Error(), func(t *testing.T) {
				lstat := os.Lstat
				readlink := os.Readlink
				if stage == "lstat" {
					lstat = func(string) (os.FileInfo, error) { return nil, cause }
					readlink = func(string) (string, error) {
						t.Fatal("readlink after lstat error")
						return "", nil
					}
				} else {
					readlink = func(string) (string, error) { return "refs/heads/main", cause }
				}
				if gitHeadSignatureWith(head, lstat, readlink, os.Stat) {
					t.Fatal("metadata error established a Git HEAD signature")
				}
			})
		}
	}
}
