//go:build windows

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

type windowsLinkInfo struct {
	os.FileInfo
	mode       os.FileMode
	attributes uint32
}

func (info windowsLinkInfo) Mode() os.FileMode { return info.mode }
func (info windowsLinkInfo) Sys() any {
	return &syscall.Win32FileAttributeData{FileAttributes: info.attributes}
}

func TestWindowsPhysicalLinkModes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       os.FileMode
		attributes uint32
		link       bool
	}{
		{"symlink", os.ModeSymlink, windows.FILE_ATTRIBUTE_REPARSE_POINT, true},
		{"junction", os.ModeIrregular, windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DIRECTORY, true},
		{"unknown directory reparse", os.ModeIrregular, windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DIRECTORY, true},
		{"ordinary directory", os.ModeDir, windows.FILE_ATTRIBUTE_DIRECTORY, false},
		{"irregular non-reparse", os.ModeIrregular, windows.FILE_ATTRIBUTE_DIRECTORY, false},
		{"non-directory reparse", os.ModeIrregular, windows.FILE_ATTRIBUTE_REPARSE_POINT, false},
		{"regular reparse data", 0, windows.FILE_ATTRIBUTE_REPARSE_POINT, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := physicalLink(windowsLinkInfo{mode: tc.mode, attributes: tc.attributes}); got != tc.link {
				t.Errorf("physical link=%v want %v", got, tc.link)
			}
		})
	}
}

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
	resolved, err := nativePhysical(raw)
	if err != nil || !strings.EqualFold(resolved, strings.TrimPrefix(opened, `\\?\`)) {
		t.Fatalf("hook target %q (%v) differs from native-open identity %q", resolved, err, opened)
	}
	// The native resolver must match Win32, but file-tool protection is the
	// union of native identity and the legacy physical link/.. witness.
	var shell Metadata
	if !Protected(raw, root, "", root) || !shell.Protected(raw, root, "", root) {
		t.Fatal("Bash policy lost its physical link/.. credential witness")
	}
	metadata := Metadata{fileTools: true}
	for _, name := range []string{raw, `junction\..\credentials`, "junction/../credentials"} {
		if !FileProtected(name, root, "", root) || !metadata.Protected(name, root, "", root) {
			t.Errorf("file tools lost the legacy physical credential witness: %q", name)
		}
	}
	configured := filepath.Join(root, ".aws", "credentials")
	if !FileConfiguredProtected(raw, root, "", root, configured) || !FileConfiguredTreeProtected(raw, root, root, configured) {
		t.Fatal("native configured-path checks lost the legacy physical witness")
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
	next := Metadata{fileTools: true}
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

func TestWindowsConfiguredIdentityPublicControls(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME"} {
		t.Setenv(key, "")
	}
	configured := filepath.Join(root, "custom.cfg")
	t.Setenv("KUBECONFIG", configured)
	for _, name := range []string{"README.md", `print(open("README.md").read())`, `open my $f, "<", "README.md"; print <$f>`} {
		var metadata Metadata
		if Protected(name, root, "", root) || metadata.Protected(name, root, "", root) {
			t.Errorf("public operand matched missing configured identity: %q", name)
		}
	}
	if !ConfiguredProtected("custom.cfg", root, "", root, configured) {
		t.Fatal("missing configured target lost its lexical witness")
	}
}

func TestWindowsGitIdentityAndResolutionErrors(t *testing.T) {
	root := t.TempDir()
	repo, git, public := filepath.Join(root, "repo"), filepath.Join(root, "metadata"), filepath.Join(root, "public")
	for _, dir := range []string{repo, git, public} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(repo, ".git")
	if err := os.WriteFile(marker, []byte("gitdir: ../metadata\n"), 0600); err != nil {
		t.Fatal(err)
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "junction")
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", alias, git).CombinedOutput(); err != nil {
		t.Fatalf("required Git junction fixture: %v (%s)", err, output)
	}
	// Exercise the identity walk without first replacing the junction spelling
	// with its final name. The missing target retains its existing ancestors.
	for _, name := range []string{alias, filepath.Join(alias, "config"), filepath.Join(alias, "missing", "new.txt")} {
		if !nativeGitProtected(name, repo, "", root) {
			t.Errorf("Git directory identity was lost for %q", name)
		}
	}
	if nativeGitProtected(filepath.Join(public, "new.txt"), repo, "", root) {
		t.Fatal("public target outside the Git identity denied")
	}
	for _, contents := range []string{"not a gitdir", "gitdir: ", "gitdir: C:relative", "gitdir: ../missing", "gitdir: ../metadata\nextra", strings.Repeat("x", 4097)} {
		if err := os.WriteFile(marker, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if !nativeGitProtected(filepath.Join(public, "new.txt"), repo, "", root) {
			t.Errorf("ambiguous repository marker did not deny: %q", contents)
		}
	}
}

func TestWindowsPolicyAndFileToolIdentityModes(t *testing.T) {
	root := t.TempDir()
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "GH_CONFIG_DIR", "XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_DIR", "GIT_COMMON_DIR"} {
		t.Setenv(key, "")
	}
	for _, name := range []string{"README.md", `print(open("README.md").read())`, `n = 5 // 2`, "public:stream", "node:20", "-ihttps://synthetic.invalid/simple"} {
		t.Run(name, func(t *testing.T) {
			var metadata Metadata
			if Protected(name, root, "", root) || metadata.Protected(name, root, "", root) || ConfigWriteProtected(name, root, "", root, "", "") {
				t.Fatal("inert Bash operand borrowed native file-tool validation or identity")
			}
			if !ValidPath(name) && (!FileProtected(name, root, "", root) || !FileConfigWriteProtected(name, root, "", root, "", "")) {
				t.Fatal("ambiguous native file target borrowed the Bash operand exemption")
			}
		})
	}
	configured, alias := filepath.Join(root, "custom.cfg"), filepath.Join(root, "public.cfg")
	if err := os.WriteFile(configured, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(configured, alias); err != nil {
		t.Fatalf("required identity alias: %v", err)
	}
	t.Setenv("KUBECONFIG", configured)
	var metadata Metadata
	if Protected(alias, root, "", root) || metadata.Protected(alias, root, "", root) || ConfiguredProtected(alias, root, "", root, configured) {
		t.Fatal("Bash policy gained native hardlink identity matching")
	}
	if !FileProtected(alias, root, "", root) || !FileConfiguredProtected(alias, root, "", root, configured) || !NativeProtected(alias, root, "", root) {
		t.Fatal("native file/search tools lost configured credential identity")
	}
}
