//go:build windows

package hook

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/avhn/secret/internal/hook/paths"
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

func TestWindowsLocalUNCStoreIdentities(t *testing.T) {
	home, work := windowsHookFixture(t)
	// Outside HOME is intentional: a shared store-directory basename must not
	// lose the same lexical credential rules that apply to a local Unix path.
	outside := filepath.Join(work, ".aws")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credentials", "config", "public.txt"} {
		if err := os.WriteFile(filepath.Join(outside, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unc := windowsHookShare(t, outside)
	computer, err := os.Hostname()
	if err != nil || computer == "" {
		t.Fatalf("required computer-name UNC fixture: %v", err)
	}
	share := strings.TrimPrefix(unc, `\\localhost\`)
	for _, host := range []string{"localhost", "127.0.0.1", computer} {
		root := `\\` + host + `\` + share
		for _, suffix := range []string{"credentials", "config", `missing\..\credentials`} {
			checkWindowsAlias(t, work, root+`\`+suffix, true)
		}
		checkWindowsAlias(t, work, root+`\public.txt`, false)
		checkWindowsAlias(t, work, root+`\missing\new.txt`, false)
	}
	// User-supplied extended/device paths and bracketed IPv6 UNC names remain
	// ambiguous and denied, not newly normalized into allowed Win32 paths.
	for _, name := range []string{`\\?\UNC\localhost\` + share + `\credentials`, `\\[::1]\` + share + `\credentials`} {
		for _, tool := range []string{"Read", "Write"} {
			windowsHookCheck(t, tool, work, map[string]any{"file_path": name}, "file access targets a protected store")
		}
		windowsHookCheck(t, "apply_patch", work, map[string]any{"command": "*** Begin Patch\n*** Delete File: " + name + "\n*** End Patch"}, "command too complex to analyse for secret access; split it or use secret run")
	}
	// Querying a nonexistent local share must never certify a public basename.
	missing := `\\localhost\secret-hook-missing-` + strings.ToLower(rand.Text()) + `\public.txt`
	checkWindowsAlias(t, work, missing, true)
	// Do not alter administrative shares. Use the existing share to reach only
	// this test's disposable fixture and require a real public-open witness.
	adminFixture := outside
	if !strings.EqualFold(filepath.VolumeName(adminFixture), "C:") {
		// Some runners place TEMP on D:. Keep the required C$ case synthetic
		// rather than silently substituting a different administrative share.
		root, err := os.MkdirTemp(`C:\Windows\Temp`, "secret-hook-admin-")
		if err != nil {
			t.Fatalf("required C$ fixture unavailable: %v", err)
		}
		t.Cleanup(func() {
			if err := os.RemoveAll(root); err != nil {
				t.Errorf("synthetic C$ fixture cleanup: %v", err)
			}
		})
		adminFixture = filepath.Join(root, ".aws")
		if err := os.Mkdir(adminFixture, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"credentials", "public.txt"} {
			if err := os.WriteFile(filepath.Join(adminFixture, name), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	admin := `\\localhost\C$` + strings.TrimPrefix(adminFixture, filepath.VolumeName(adminFixture))
	if _, err := os.Stat(admin + `\public.txt`); err != nil {
		t.Fatalf("required administrative C$ fixture unavailable: %v", err)
	}
	checkWindowsAlias(t, work, admin+`\credentials`, true)
	checkWindowsAlias(t, work, admin+`\public.txt`, false)
	// A junction hides the basename without SMB or a HOME prefix too.
	junction := filepath.Join(home, "outside-junction")
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Fatalf("required outside-HOME junction fixture: %v (%s)", err, output)
	}
	checkWindowsAlias(t, work, junction+`\credentials`, true)
	checkWindowsAlias(t, work, junction+`\public.txt`, false)
}

func TestWindowsUNCProtectedRootRoles(t *testing.T) {
	home, work := windowsHookFixture(t)
	for _, tc := range []struct{ directory, leaf string }{
		{".secrets", "data.txt"}, {".aws", "credentials"}, {".ssh", "id_synthetic"},
		{".kube", "config"}, {".docker", "config.json"}, {".config", `gh\hosts.yml`},
		{`.config\gh`, "hosts.yml"}, {`.config\gcloud`, "credentials.db"},
		{".terraform.d", "credentials.tfrc.json"}, {".cargo", "credentials.toml"},
	} {
		t.Run(tc.directory, func(t *testing.T) {
			directory := filepath.Join(home, tc.directory)
			if err := os.MkdirAll(filepath.Dir(filepath.Join(directory, tc.leaf)), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, tc.leaf), []byte("synthetic"), 0600); err != nil {
				t.Fatal(err)
			}
			unc := windowsHookShare(t, directory)
			checkWindowsAlias(t, work, unc+`\`+tc.leaf, true)
			for _, tool := range []string{"Glob", "Grep"} {
				windowsHookCheck(t, tool, work, map[string]any{"path": unc, "output_mode": "files_with_matches"}, "file access targets a protected store")
			}
		})
	}
}

func TestWindowsUNCGitDirectoryRoots(t *testing.T) {
	home, work := windowsHookFixture(t)
	git := filepath.Join(home, "metadata")
	for _, dir := range []string{git, filepath.Join(git, "objects"), filepath.Join(git, "refs")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"HEAD", "config"} {
		if err := os.WriteFile(filepath.Join(git, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	unc := windowsHookShare(t, git)
	// No repository marker in cwd: the HEAD/objects/refs signature at a share
	// or volume root must suffice, independently of repository discovery.
	checkWindowsGitAlias(t, work, unc+`\config`, true)
	checkWindowsGitAlias(t, work, unc+`\missing\new.txt`, true)
	drive := windowsHookSubst(t, git)
	checkWindowsGitAlias(t, work, drive+"config", true)
	if !paths.FileConfigWriteProtected(unc, work, "", home, "", "") || !paths.FileConfigWriteProtected(drive, work, "", home, "", "") {
		t.Fatal("Git metadata at the exposed share/drive root was not recognized")
	}
	// Without a signature, discovery from a gitfile still protects by identity.
	if err := os.Remove(filepath.Join(git, "HEAD")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".git"), []byte("gitdir: "+git+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	checkWindowsGitAlias(t, work, unc+`\config`, true)
	public := windowsHookShare(t, home)
	checkWindowsGitAlias(t, work, public+`\public.txt`, false)
}

func TestWindowsUNCProtectedIdentityWitness(t *testing.T) {
	home, work := windowsHookFixture(t)
	physical := filepath.Join(work, "metadata")
	if err := os.Mkdir(physical, 0700); err != nil {
		t.Fatal(err)
	}
	for _, leaf := range []string{"credentials", "config", "public.txt"} {
		if err := os.WriteFile(filepath.Join(physical, leaf), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", filepath.Join(home, ".aws"), physical).CombinedOutput(); err != nil {
		t.Fatalf("required protected-root junction fixture: %v (%s)", err, output)
	}
	// Neither the final DOS name, the share name nor the substituted-drive
	// spelling contains .aws. Only the protected root's handle identity does.
	unc := windowsHookShare(t, physical)
	drive := windowsHookSubst(t, physical)
	for _, root := range []string{physical + `\`, unc + `\`, drive} {
		checkWindowsAlias(t, work, root+"credentials", true)
		checkWindowsAlias(t, work, root+"config", true)
		checkWindowsAlias(t, work, root+"public.txt", false)
	}
}
