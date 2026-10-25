//go:build windows

package hook

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Create only a new random current-user share backed by a disposable fixture.
// Never use, modify or remove an existing administrative share or provider target.
func windowsHookShare(t *testing.T, directory string) string {
	t.Helper()
	share := "secret-hook-" + strings.ToLower(rand.Text())
	name, _ := windows.UTF16PtrFromString(share)
	path, _ := windows.UTF16PtrFromString(directory)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	info := struct {
		Name                              *uint16
		Type                              uint32
		Remark                            *uint16
		Permissions, MaxUses, CurrentUses uint32
		Path, Password                    *uint16
		Reserved                          uint32
		Descriptor                        *windows.SECURITY_DESCRIPTOR
	}{Name: name, MaxUses: ^uint32(0), Path: path, Descriptor: descriptor}
	api := windows.NewLazySystemDLL("netapi32.dll")
	add, remove := api.NewProc("NetShareAdd"), api.NewProc("NetShareDel")
	var parameter uint32
	status, _, _ := add.Call(0, 502, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(info)
	runtime.KeepAlive(descriptor)
	if status != 0 {
		t.Fatalf("required synthetic hook UNC share: status %d, parameter %d", status, parameter)
	}
	t.Cleanup(func() {
		status, _, _ := remove.Call(0, uintptr(unsafe.Pointer(name)), 0)
		if status != 0 {
			t.Errorf("synthetic hook UNC share cleanup failed: status %d", status)
		}
	})
	return `\\localhost\` + share
}

func TestWindowsUNCFileAndPatchAliases(t *testing.T) {
	home, work := windowsHookFixture(t)
	if err := os.Mkdir(filepath.Join(home, ".secrets"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"public.txt", ".yarnrc.yml", ".gitconfig", ".secrets/data.txt"} {
		if err := os.WriteFile(filepath.Join(home, filepath.FromSlash(name)), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unc := windowsHookShare(t, home)
	checkWindowsAlias(t, work, unc+`\public.txt`, false)
	checkWindowsAlias(t, work, unc+`\.yarnrc.yml`, true)
	checkWindowsAlias(t, work, unc+`\.secrets\data.txt`, true)
	// The share name itself hides .secrets; directory identity retains the role.
	private := windowsHookShare(t, filepath.Join(home, ".secrets"))
	checkWindowsAlias(t, work, private+`\data.txt`, true)
	checkWindowsAlias(t, work, private+`\missing\new.txt`, true)
	for _, tool := range []string{"Glob", "Grep"} {
		windowsHookCheck(t, tool, work, map[string]any{"path": private, "output_mode": "files_with_matches"}, "file access targets a protected store")
		windowsHookCheck(t, tool, work, map[string]any{"path": unc + `\public.txt`, "output_mode": "files_with_matches"}, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "public.txt"))
	checkWindowsAlias(t, work, unc+`\public.txt`, true)
	t.Setenv("AWS_CONFIG_FILE", "")
	windowsHookCheck(t, "Read", work, map[string]any{"file_path": unc + `\.gitconfig`}, "")
	windowsHookCheck(t, "Write", work, map[string]any{"file_path": unc + `\.gitconfig`}, "file access targets a protected store")
	windowsHookCheck(t, "apply_patch", work, map[string]any{"command": "*** Begin Patch\n*** Delete File: " + unc + `\.gitconfig` + "\n*** End Patch"}, "patch targets a protected store")
}
