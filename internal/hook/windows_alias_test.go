//go:build windows

package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
	"golang.org/x/sys/windows"
)

func TestWindowsFileAndPatchAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	for _, dir := range []string{filepath.Join(home, ".secrets"), filepath.Join(home, "public")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "data.txt"), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{
		{"protected-link", filepath.Join(home, ".secrets", "data.txt")},
		{"public-link", filepath.Join(home, "public", "data.txt")},
		{"dangling-link", filepath.Join(home, ".env")},
	} {
		if err := os.Symlink(pair[1], filepath.Join(work, pair[0])); err != nil {
			t.Fatalf("required native symlink fixture: %v", err)
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"protected-junction", filepath.Join(home, ".secrets")}, {"public-junction", filepath.Join(home, "public")}} {
		cmd := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", filepath.Join(work, pair[0]), pair[1])
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("required native junction fixture: %v (%s)", err, output)
		}
	}
	for _, tc := range []struct {
		name string
		deny bool
	}{
		{"protected-link", true}, {"public-link", false}, {"dangling-link", true},
		{`protected-junction\data.txt`, true}, {`protected-junction\missing\new.txt`, true},
		{`public-junction\data.txt`, false}, {`public-junction\missing\new.txt`, false},
	} {
		checkWindowsAlias(t, work, tc.name, tc.deny)
	}
	// A configured credential with an ordinary basename is also protected through
	// a reparse alias, not only through a credential-looking resolved name.
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "public", "data.txt"))
	checkWindowsAlias(t, work, "public-link", true)
	checkWindowsAlias(t, work, `public-junction\data.txt`, true)
}

func checkWindowsAlias(t *testing.T, work, name string, deny bool) {
	t.Helper()
	for _, tool := range []string{"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"} {
		field, reason := "file_path", ""
		if tool == "NotebookEdit" {
			field = "notebook_path"
		}
		if deny {
			reason = "file access targets a protected store"
		}
		windowsHookCheck(t, tool, work, map[string]any{field: name}, reason)
	}
	reason := ""
	if deny {
		reason = "patch targets a protected store"
	}
	for _, header := range []string{
		"*** Add File: " + name + "\n+synthetic",
		"*** Update File: " + name + "\n@@\n-old\n+new",
		"*** Delete File: " + name,
		"*** Update File: public.txt\n*** Move to: " + name + "\n@@\n-old\n+new",
		"*** Update File: " + name + "\n*** Move to: public.txt\n@@\n-old\n+new",
	} {
		windowsHookCheck(t, "apply_patch", work, map[string]any{"command": "*** Begin Patch\n" + header + "\n*** End Patch"}, reason)
	}
}

func TestWindowsShortFileAndPatchAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	for _, name := range []string{"long-synthetic-name.secret", "long-synthetic-public-name.txt"} {
		long := filepath.Join(home, name)
		if err := os.WriteFile(long, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
		pointer, err := windows.UTF16PtrFromString(long)
		if err != nil {
			t.Fatal(err)
		}
		buffer := make([]uint16, 32768)
		n, err := windows.GetShortPathName(pointer, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 || n >= uint32(len(buffer)) {
			t.Fatalf("short alias lookup failed: %v", err)
		}
		short := windows.UTF16ToString(buffer[:n])
		if strings.EqualFold(filepath.Base(short), name) {
			t.Log("8.3 basename aliases disabled on fixture volume; resolved long spelling still checked")
		}
		checkWindowsAlias(t, work, short, strings.HasSuffix(name, ".secret"))
		checkWindowsAlias(t, work, strings.ToUpper(filepath.ToSlash(short)), strings.HasSuffix(name, ".secret"))
	}
}

// Allocate only an unused drive letter and remove only this test's substitution.
// Missing subst or an unavailable letter fails required alias coverage explicitly.
func windowsHookSubst(t *testing.T, directory string) string {
	t.Helper()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	subst := filepath.Join(system, "subst.exe")
	if _, err := os.Stat(subst); err != nil {
		t.Fatalf("required subst drive fixture unavailable: %v", err)
	}
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		t.Fatal(err)
	}
	for letter := byte('Z'); letter >= 'E'; letter-- {
		if drives&(1<<uint(letter-'A')) != 0 {
			continue
		}
		drive := string(letter) + ":"
		if output, err := exec.Command(subst, drive, directory).CombinedOutput(); err != nil {
			t.Fatalf("required subst drive fixture: %v (%s)", err, output)
		}
		t.Cleanup(func() {
			if output, err := exec.Command(subst, drive, "/D").CombinedOutput(); err != nil {
				t.Errorf("synthetic subst cleanup: %v (%s)", err, output)
			}
			current, err := windows.GetLogicalDrives()
			if err != nil || current&(1<<uint(letter-'A')) != 0 {
				t.Errorf("synthetic subst cleanup did not remove %s: %v", drive, err)
			}
		})
		return drive + `\`
	}
	t.Fatal("required subst drive fixture: no unused drive letter")
	return ""
}

func checkWindowsGitAlias(t *testing.T, work, name string, deny bool) {
	t.Helper()
	windowsHookCheck(t, "Read", work, map[string]any{"file_path": name}, "")
	for _, tool := range []string{"Edit", "Write", "MultiEdit", "NotebookEdit"} {
		field, reason := "file_path", ""
		if tool == "NotebookEdit" {
			field = "notebook_path"
		}
		if deny {
			reason = "file access targets a protected store"
		}
		windowsHookCheck(t, tool, work, map[string]any{field: name}, reason)
	}
	reason := ""
	if deny {
		reason = "patch targets a protected store"
	}
	for _, header := range []string{
		"*** Add File: " + name + "\n+synthetic",
		"*** Update File: " + name + "\n@@\n-old\n+new",
		"*** Delete File: " + name,
		"*** Update File: public.txt\n*** Move to: " + name + "\n@@\n-old\n+new",
	} {
		windowsHookCheck(t, "apply_patch", work, map[string]any{"command": "*** Begin Patch\n" + header + "\n*** End Patch"}, reason)
	}
}

func TestWindowsSubstProtectedAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	outside := filepath.Join(work, ".aws")
	for _, dir := range []string{outside, filepath.Join(home, ".ssh")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(outside, "credentials"), filepath.Join(outside, "public.txt"), filepath.Join(home, ".ssh", "id_synthetic")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Both the HOME directory and a store basename outside HOME can be hidden
	// at a substituted drive root. Public siblings must not be blanket-denied.
	drive := windowsHookSubst(t, outside)
	checkWindowsAlias(t, work, drive+"credentials", true)
	checkWindowsAlias(t, work, drive+`missing\credentials`, false)
	checkWindowsAlias(t, work, drive+"public.txt", false)
	private := windowsHookSubst(t, filepath.Join(home, ".ssh"))
	checkWindowsAlias(t, work, private+"id_synthetic", true)
	checkWindowsAlias(t, work, private+"id_synthetic.pub", false)
	for _, tool := range []string{"Glob", "Grep"} {
		windowsHookCheck(t, tool, work, map[string]any{"path": drive, "output_mode": "files_with_matches"}, "file access targets a protected store")
	}
}

func TestWindowsGitDirectoryIdentityAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	git := filepath.Join(work, ".git")
	if err := os.Mkdir(git, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(git, "config"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	// Deliberately omit HEAD/objects/refs: discovery from cwd must retain the
	// gitdir identity independently of a signature or protected basename.
	drive := windowsHookSubst(t, git)
	checkWindowsGitAlias(t, work, drive+"config", true)
	checkWindowsGitAlias(t, work, drive+`missing\new.txt`, true)
	if !paths.ConfigWriteProtected(drive+"config", home, work, home, "", "") {
		t.Fatal("workdir repository identity was not checked")
	}
	if !paths.ConfigWriteProtected(drive+"config", work, home, home, "", "") {
		t.Fatal("cwd repository identity was lost to workdir")
	}
	// A gitfile can name a separate directory with an ordinary basename.
	separate := filepath.Join(home, "metadata")
	if err := os.Mkdir(separate, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(git); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(git, []byte("gitdir: "+separate+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	other := windowsHookSubst(t, separate)
	checkWindowsGitAlias(t, work, other+`missing\new.txt`, true)
	if !paths.ConfigWriteProtected(other+"config", home, work, home, "", "") {
		t.Fatal("workdir gitfile identity was not checked")
	}
	checkWindowsGitAlias(t, work, filepath.Join(home, "public.txt"), false)
}
