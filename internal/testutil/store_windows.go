//go:build windows

package testutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// TrustStoreParent changes only a disposable fixture to a home-style DACL.
// The caller creates owner-only children before broadening the parent.
func TrustStoreParent(t testing.TB, path string, inherited bool) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	set := func(target string, control windows.SECURITY_INFORMATION, dacl *windows.ACL) {
		name, err := windows.UTF16PtrFromString(target)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(handle)
		if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|control, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	if inherited {
		// The enclosing t.TempDir is disposable too. Use real inherited ACEs.
		set(filepath.Dir(path), windows.PROTECTED_DACL_SECURITY_INFORMATION, acl)
		empty, err := windows.SecurityDescriptorFromString("D:P")
		if err != nil {
			t.Fatal(err)
		}
		emptyACL, _, err := empty.DACL()
		if err != nil {
			t.Fatal(err)
		}
		set(path, windows.UNPROTECTED_DACL_SECURITY_INFORMATION, emptyACL)
		runtime.KeepAlive(empty)
	} else {
		set(path, windows.PROTECTED_DACL_SECURITY_INFORMATION, acl)
	}
	runtime.KeepAlive(descriptor)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	actual, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	actualACL, _, err := actual.DACL()
	if err != nil || actualACL == nil || actualACL.AceCount != 3 {
		t.Fatal("fixture lacks trusted ACEs")
	}
	for i := uint32(0); i < 3; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(actualACL, i, &ace) != nil || (ace.Header.AceFlags&windows.INHERITED_ACE != 0) != inherited {
			t.Fatal("fixture inheritance mismatch")
		}
	}
	runtime.KeepAlive(actual)
}

// AddStoreParentUsersRead broadens only a disposable trusted-parent fixture.
func AddStoreParentUsersRead(t testing.TB, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(descriptor)
}
