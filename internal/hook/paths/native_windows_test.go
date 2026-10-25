//go:build windows

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

func TestWindowsNativeParentTraversal(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{filepath.Join(root, ".aws", "child"), filepath.Join(root, "public")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(root, "credentials"), filepath.Join(root, ".aws", "credentials")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "junction")
	cmd := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", link, filepath.Join(root, ".aws", "child"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("required junction fixture: %v (%s)", err, output)
	}
	// Use an actual Win32 open, not filepath.Clean or a predicted target, as the
	// witness for the binding native junction-plus-parent traversal contract.
	raw := link + `\..\credentials`
	pointer, _ := windows.UTF16PtrFromString(raw)
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), "synthetic-native")
	t.Cleanup(func() { _ = file.Close() })
	opened, err := secure.FinalPath(file)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := physical(raw)
	if err != nil || !strings.EqualFold(resolved, strings.TrimPrefix(opened, `\\?\`)) {
		t.Fatalf("hook target %q (%v) differs from native-open identity %q", resolved, err, opened)
	}
	if FileProtected(raw, root, "", root) {
		t.Fatal("native public parent traversal borrowed Unix link/.. semantics")
	}
	var metadata Metadata
	if metadata.Protected(raw, root, "", root) {
		t.Fatal("cached resolver differs from the native public traversal")
	}
	// Cache identity for one analysis only. The next analysis must observe a
	// changed reparse target rather than reusing an earlier public resolution.
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(filepath.Join(root, "credentials"), alias); err != nil {
		t.Fatalf("required symlink fixture: %v", err)
	}
	if metadata.Protected(alias, root, "", root) {
		t.Fatal("public alias denied")
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".aws", "credentials"), alias); err != nil {
		t.Fatal(err)
	}
	var next Metadata
	if !next.Protected(alias, root, "", root) {
		t.Fatal("native metadata survived into another analysis")
	}
}

func TestWindowsNativeFileAmbiguity(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{`C:relative`, `\rooted`, `\\?\C:\public`, `\\.\C:\public`, `\??\C:\public`, `public:stream`, `public::$DATA`, `NUL`, `COM1.txt`, `LPT¹.log`, `public.`, `public `} {
		if !FileProtected(name, root, "", root) {
			t.Errorf("ambiguous file target allowed: %q", name)
		}
	}
	for _, name := range []string{"public.txt", `src\public.go`, "src/public.go", filepath.Join(root, "public.txt"), strings.ToUpper(filepath.Join(root, "public.txt"))} {
		if FileProtected(name, root, "", root) {
			t.Errorf("public target denied: %q", name)
		}
	}
}
