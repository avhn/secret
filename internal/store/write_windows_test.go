//go:build windows

package store

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
	"golang.org/x/sys/windows"
)

func nativeFixtureHandle(t *testing.T, path string, access, share uint32) *os.File {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(handle), "synthetic-native")
	t.Cleanup(func() { file.Close() })
	return file
}

func TestWindowsLockDeletePending(t *testing.T) {
	dir := testutil.TempDir(t)
	root, err := openWriteRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := secure.CreatePrivateDirectory(root, ".write-lock"); err != nil {
		t.Fatal(err)
	}
	handle := nativeFixtureHandle(t, filepath.Join(dir, ".write-lock"), windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	// FileDispositionInfo (4) sets legacy delete-pending until the last handle
	// closes, unlike POSIX unlink which immediately releases the name.
	disposition := byte(1)
	if err := windows.SetFileInformationByHandle(windows.Handle(handle.Fd()), windows.FileDispositionInfo, &disposition, 1); err != nil {
		t.Fatal(err)
	}
	if err := secure.CreatePrivateDirectory(root, ".write-lock"); err != secure.ErrPrivateBusy {
		t.Fatalf("delete-pending create classification: %v", err)
	}
	// Release only after the acquisition loop has encountered the native state.
	released := make(chan struct{})
	go func() { time.Sleep(150 * time.Millisecond); handle.Close(); close(released) }()
	called := false
	err = withLock(dir, time.Second, func() error { called = true; return nil })
	<-released
	if err != nil || !called {
		t.Fatalf("pending deletion did not resolve: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".write-lock")); !os.IsNotExist(err) {
		t.Fatal("lock cleanup left a directory")
	}
}

func TestWindowsPermanentACLDenial(t *testing.T) {
	dir := testutil.TempDir(t)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	handle := nativeFixtureHandle(t, dir, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	original, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := original.DACL()
	if err != nil {
		t.Fatal(err)
	}
	// Restore only this disposable fixture before testing.T's cleanup.
	defer func() {
		if err := windows.SetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Error(err)
		}
	}()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FR;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	deniedACL, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, deniedACL, nil); err != nil {
		t.Fatal(err)
	}
	if err := secure.CreatePrivateDirectory(root, ".write-lock"); err != secure.ErrPrivateFile || lockBusy(err) {
		t.Fatalf("ACL denial classified as contention: %v", err)
	}
	if err := withLock(dir, time.Second, func() error { t.Fatal("ACL-denied lock entered callback"); return nil }); err == nil {
		t.Fatal("ACL-denied root accepted")
	}
	calls := 0
	if err := retryPrivateBusy(func() error { calls++; return windows.ERROR_ACCESS_DENIED }); err != windows.ERROR_ACCESS_DENIED || calls != 1 {
		t.Fatal("permanent access denial was retried")
	}
}

func TestWindowsReplacementAndDurability(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "open reader", true: "read-only destination"}[blocked], func(t *testing.T) {
			dir := testutil.TempDir(t)
			path := filepath.Join(dir, "store.secret")
			old := []byte("KEY=synthetic-before\n")
			if err := testutil.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			root, err := openWriteRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			reader, err := secure.OpenPrivateFile(root, "store.secret")
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if blocked {
				if err := os.Chmod(path, 0400); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(path, 0600)
			}
			next := []byte("KEY=synthetic-after\n")
			err = atomicReplace(root, "store.secret", next)
			if blocked && err == nil {
				t.Fatal("replaced a read-only destination")
			}
			if !blocked && err != nil {
				t.Fatalf("replacement with an open sharing reader: %v", err)
			}
			got, err := ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := next
			if blocked {
				want = old
			}
			if !bytes.Equal(got, want) {
				t.Fatal("publication damaged destination bytes")
			}
			prior := make([]byte, len(old))
			if _, err := reader.Read(prior); err != nil || !bytes.Equal(prior, old) {
				t.Fatal("replacement changed an already-open identity")
			}
			assertPrivateFixture(t, path)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("replacement leaked scratch")
			}
			if err := syncManifestDirectory(root); err != nil {
				t.Fatal("directory durability policy rejected a valid root")
			}
			root.Close()
			if err := syncManifestDirectory(root); err != secure.ErrRecovery {
				t.Fatal("closed directory ignored by durability policy")
			}
		})
	}
}

func TestWindowsLockedDestinationPreservesBytes(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "store.secret")
	original := []byte("KEY=synthetic-original\n")
	if err := testutil.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	// Without FILE_SHARE_READ even the private target check must fail boundedly.
	blocker := nativeFixtureHandle(t, path, windows.GENERIC_READ, windows.FILE_SHARE_WRITE)
	root, err := openWriteRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := atomicReplace(root, "store.secret", []byte("KEY=synthetic-new\n")); err == nil {
		t.Fatal("locked target accepted")
	}
	blocker.Close()
	if got, err := ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("locked-target failure changed old bytes")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("locked-target failure leaked scratch")
	}
}

func TestWindowsPrivateReadAndMutationRejectModeOnlyFixtures(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "mode-only.secret")
	original := []byte("KEY=synthetic-unprotected\n")
	if err := testutil.WriteFile(path, original, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(path); err == nil {
		t.Fatal("mode-only read accepted")
	}
	if err := testStash(path, "KEY", nil, []byte("replacement")); err == nil {
		t.Fatal("mode-only stash accepted")
	}
	if err := (FileTransaction{SecretsDir: dir, Path: path}).Apply([]Mutation{{Kind: MutationDelete, Key: "KEY"}}); err != secure.ErrTransaction {
		t.Fatal("mode-only mutation accepted")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("rejected writes changed unprotected fixture")
	}
}

func makeWindowsJunction(t *testing.T, link, target string) {
	t.Helper()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", link, target)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("required junction fixture: %v (%s)", err, output)
	}
}

func TestWindowsJunctionAndNativeParentTraversal(t *testing.T) {
	base := testutil.TempDir(t)
	target := filepath.Join(base, "physical")
	if err := testutil.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	makeWindowsJunction(t, junction, target)
	if ValidateDirectory(junction) == nil {
		t.Fatal("final junction accepted as a store directory")
	}
	for _, dir := range []string{base, target} {
		if err := testutil.WriteFile(filepath.Join(dir, "expected.secret"), []byte("KEY=synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Do not filepath.Join away the parent component before the native open.
	path := junction + `\..\expected.secret`
	name, _ := windows.UTF16PtrFromString(path)
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	native := os.NewFile(uintptr(handle), "synthetic-native")
	defer native.Close()
	root, err := openReadRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	opened, err := openNoFollow(root, filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	a, err := native.Stat()
	if err != nil {
		t.Fatal(err)
	}
	b, err := opened.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("private traversal disagrees with native Win32 lexical traversal")
	}
	identity, err := secure.FinalPath(opened)
	if err != nil || !strings.HasSuffix(strings.ToLower(identity), `\expected.secret`) {
		t.Fatal("native identity unavailable")
	}
	if _, err := ReadFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsLoopbackUNCPrivateStorage(t *testing.T) {
	// SHARE_INFO_502 gives this disposable share an explicit current-user DACL.
	// Never use or alter an existing administrative share, credentials or stores.
	dir := testutil.TempDir(t)
	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	shareName := "secret-test-" + token
	name, _ := windows.UTF16PtrFromString(shareName)
	path, _ := windows.UTF16PtrFromString(dir)
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
		t.Fatalf("required isolated UNC share unavailable: status %d, parameter %d", status, parameter)
	}
	t.Cleanup(func() {
		status, _, _ := remove.Call(0, uintptr(unsafe.Pointer(name)), 0)
		if status != 0 {
			t.Errorf("synthetic share cleanup failed: status %d", status)
		}
	})
	unc := `\\localhost\` + shareName + `\store`
	file := unc + `\synthetic.secret`
	if err := StashWithSecretsDir(unc, file, "KEY", nil, []byte("synthetic-unc")); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFile(file); err != nil || !bytes.Equal(got, []byte("KEY=synthetic-unc\n")) {
		t.Fatal("private UNC round trip failed")
	}
	assertPrivateFixture(t, file)
	rootFile := `\\localhost\` + shareName + `\root.secret`
	if err := StashWithSecretsDir(unc, rootFile, "KEY", nil, []byte("synthetic-share-root")); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadFile(rootFile); err != nil || !bytes.Equal(got, []byte("KEY=synthetic-share-root\n")) {
		t.Fatal("private UNC share-root round trip failed")
	}
	assertPrivateFixture(t, rootFile)
}

func TestWindowsBusyRetryIsBounded(t *testing.T) {
	calls := 0
	start := time.Now()
	err := retryPrivateBusy(func() error { calls++; return secure.ErrPrivateBusy })
	if !errors.Is(err, secure.ErrPrivateBusy) || calls < 2 || time.Since(start) > 3*time.Second {
		t.Fatal("busy retry is missing or unbounded")
	}
}

func TestWindowsPrivateLockAndStaleScratch(t *testing.T) {
	dir := testutil.TempDir(t)
	root, err := openWriteRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Only protected, marked scratch belongs to the next lock owner. Keep an
	// unprotected lookalike, even if it contains the otherwise-correct marker.
	for _, name := range []string{".secret-stash.owned", ".secret-stash.unowned"} {
		if name == ".secret-stash.owned" {
			if err := secure.CreatePrivateDirectory(root, name); err != nil {
				t.Fatal(err)
			}
			child, err := secure.OpenPrivateDirectory(root, name)
			if err != nil {
				t.Fatal(err)
			}
			if err := writePrivateChild(child, "owner", []byte("secret-stash-v1\n")); err != nil {
				child.Close()
				t.Fatal(err)
			}
			child.Close()
		} else {
			if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name, "owner"), []byte("secret-stash-v1\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := WithWriteLock(dir, func() error {
		assertPrivateFixture(t, dir)
		assertPrivateFixture(t, filepath.Join(dir, ".write-lock"))
		assertPrivateFixture(t, filepath.Join(dir, ".write-lock", "token"))
		if _, err := root.Stat(".secret-stash.owned"); !os.IsNotExist(err) {
			t.Fatal("owned scratch not cleaned")
		}
		if _, err := root.Stat(".secret-stash.unowned"); err != nil {
			t.Fatal("unprotected lookalike cleaned")
		}
		// A changed token must leave the lock for manual verification.
		return testutil.WriteFile(filepath.Join(dir, ".write-lock", "token"), []byte("synthetic-different-owner\n"), 0600)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(".write-lock/token"); err != nil {
		t.Fatal("changed owner lock automatically removed")
	}
}

func TestWindowsRecoveryPublicationFailure(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.keys")
	prior := ManifestRecord{Key: "PRIOR", Account: "11111111111111111111111111111111"}
	prepared := ManifestRecord{Key: "NEW", Account: "22222222222222222222222222222222"}
	if err := UpdateManifest(path, "libsecret", prior.Key, nil, prior.Account); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = WithManifestLock(path, "libsecret", func(editor *ManifestEditor) error {
		if err := editor.PersistRecovery(RecoveryIntent{Version: MetadataVersion, Backend: "libsecret", Prepared: []ManifestRecord{prepared}, Obsolete: []ManifestRecord{prior}}); err != nil {
			return err
		}
		if err := os.Chmod(path, 0400); err != nil {
			return err
		}
		defer os.Chmod(path, 0600)
		if err := editor.Publish([]ManifestRecord{prepared}); err != secure.ErrTransaction {
			t.Fatal("publication error was ignored")
		}
		if err := editor.ClearRecovery(); err != secure.ErrRecovery {
			t.Fatal("failed publication cleared recovery")
		}
		return secure.ErrTransaction
	})
	if err != secure.ErrRecovery {
		t.Fatal("failed publication did not retain recovery status")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, original) {
		t.Fatal("failed manifest publication changed old bytes")
	}
	if _, err := ReadRecovery(path, "libsecret"); err != nil {
		t.Fatal("required recovery intent lost")
	}
	assertPrivateFixture(t, path+".recovery")
}

func TestWindowsReplacementHasNoTornReads(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "synthetic.secret")
	a := append([]byte("KEY="), bytes.Repeat([]byte("a"), 8192)...)
	b := append([]byte("KEY="), bytes.Repeat([]byte("b"), 16384)...)
	if err := testutil.WriteFile(path, a, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := openWriteRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 40; i++ {
			next := a
			if i%2 == 0 {
				next = b
			}
			if err := atomicReplace(root, "synthetic.secret", next); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for {
		got, err := ReadFile(path)
		if err != nil || (!bytes.Equal(got, a) && !bytes.Equal(got, b)) {
			<-done
			t.Fatal("atomic publication exposed a gap or torn read")
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
		}
	}
}
