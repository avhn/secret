//go:build windows

package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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
