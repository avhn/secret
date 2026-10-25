package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSamePathIdentity(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()
	left, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	right, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic aliases share actual metadata identities, without requiring
	// Windows drives/shares or symlink privileges on the test host.
	aliases := map[string]os.FileInfo{"local": left, "share": left, "other": right}
	for _, tc := range []struct {
		name, a, b string
		err        error
		want       bool
	}{
		{"existing alias", "local", "share", nil, true},
		{"different objects", "local", "other", nil, false},
		{"missing alias suffix", "local/missing/config", "share/missing/config", nil, true},
		{"different missing leaves", "local/README.md", "share/custom.cfg", nil, false},
		{"different missing parents", "local/public/config", "share/private/config", nil, false},
		{"different existing parents", "local/config", "other/config", nil, false},
		{"existing and missing", "local", "share/local", nil, false},
		{"missing and existing", "local/share", "share", nil, false},
		{"shared ancestor only", "local/public.txt", "local", nil, false},
		{"case folded suffix", "local/MISSING/CONFIG", "share/missing/config", nil, true},
		{"invalid name is not identity", "invalid", "share/config", syscall.Errno(123), false},
		{"bad pathname is not identity", "invalid", "share/config", syscall.Errno(161), false},
		{"non-directory is not identity", "invalid", "share/config", syscall.Errno(267), false},
		{"invalid filesystem operand", "invalid", "share/config", fs.ErrInvalid, false},
		{"permission remains uncertain", "invalid", "share/config", fs.ErrPermission, true},
		{"I/O remains uncertain", "invalid", "share/config", syscall.Errno(1117), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stat := func(name string) (os.FileInfo, error) {
				name = filepath.ToSlash(name)
				if name == "invalid" {
					return nil, &os.PathError{Op: "metadata", Path: name, Err: tc.err}
				}
				if info := aliases[name]; info != nil {
					return info, nil
				}
				return nil, os.ErrNotExist
			}
			for _, pair := range [][2]string{{tc.a, tc.b}, {tc.b, tc.a}} {
				if got := samePathIdentity(filepath.FromSlash(pair[0]), filepath.FromSlash(pair[1]), stat, invalidWindowsOperand); got != tc.want {
					t.Errorf("identity(%q, %q)=%v want %v", pair[0], pair[1], got, tc.want)
				}
			}
		})
	}
}

func TestSamePathIdentityBound(t *testing.T) {
	calls := 0
	name := strings.Repeat("missing"+string(os.PathSeparator), 129) + "config"
	if !samePathIdentity(name, name, func(string) (os.FileInfo, error) {
		calls++
		return nil, os.ErrNotExist
	}, invalidWindowsOperand) || calls != 256 {
		t.Fatalf("exhausted identity lookup must remain conservative: calls=%d", calls)
	}
}
