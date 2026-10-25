//go:build windows

package secure

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestPrivateWindowsErrorClassification(t *testing.T) {
	for _, tc := range []struct {
		status windows.NTStatus
		want   error
	}{
		{windows.STATUS_OBJECT_NAME_COLLISION, os.ErrExist},
		{windows.STATUS_OBJECT_NAME_NOT_FOUND, os.ErrNotExist},
		{windows.STATUS_OBJECT_PATH_NOT_FOUND, os.ErrNotExist},
		{windows.STATUS_DELETE_PENDING, ErrPrivateBusy},
		{windows.STATUS_SHARING_VIOLATION, ErrPrivateBusy},
		{windows.STATUS_ACCESS_DENIED, ErrPrivateFile},
		{windows.STATUS_INVALID_PARAMETER, ErrPrivateFile},
	} {
		if got := privateNativeError(tc.status); got != tc.want {
			t.Errorf("native status %#x: got %v, want %v", uint32(tc.status), got, tc.want)
		}
	}
}

func TestPrivateWindowsDescriptors(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, sddl string
		valid      bool
	}{
		{"owner only", "O:" + sid + "D:P(A;;FA;;;" + sid + ")", true},
		{"inheritable owner only", "O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")", true},
		{"unprotected", "O:" + sid + "D:(A;;FA;;;" + sid + ")", false},
		{"world access", "O:" + sid + "D:P(A;;FA;;;WD)", false},
		{"additional world access", "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", false},
		{"wrong owner", "O:WDD:P(A;;FA;;;" + sid + ")", false},
		{"inherit only", "O:" + sid + "D:P(A;OICIIO;FA;;;" + sid + ")", false},
		{"inherited", "O:" + sid + "D:P(A;ID;FA;;;" + sid + ")", false},
		{"empty ACL", "O:" + sid + "D:P", false},
		{"read only", "O:" + sid + "D:P(A;;FR;;;" + sid + ")", false},
		{"deny ACE", "O:" + sid + "D:P(D;;FA;;;" + sid + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			if got := checkPrivateDescriptor(descriptor, user.User.Sid); (got == nil) != tc.valid {
				t.Fatalf("descriptor acceptance = %v, want %v", got == nil, tc.valid)
			}
		})
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := descriptor.SetOwner(user.User.Sid, false); err != nil {
		t.Fatal(err)
	}
	if err := descriptor.SetDACL(nil, true, false); err != nil {
		t.Fatal(err)
	}
	if err := descriptor.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		t.Fatal(err)
	}
	if checkPrivateDescriptor(descriptor, user.User.Sid) != ErrPrivateFile {
		t.Fatal("NULL DACL accepted")
	}
}

func TestPrivateWindowsRejectsReparseHandles(t *testing.T) {
	root := privateTestRoot(t)
	original, err := CreatePrivateFile(root, "original")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("synthetic-reparse-control")
	if _, err := original.Write(payload); err != nil {
		original.Close()
		t.Fatal(err)
	}
	original.Close()
	// This is mandatory native coverage, not a privilege-dependent silent skip.
	if err := root.Symlink("original", "alias"); err != nil {
		t.Fatalf("required synthetic symlink fixture unavailable: %v", err)
	}
	if file, err := OpenPrivateFile(root, "alias"); err == nil {
		file.Close()
		t.Fatal("private read followed a final reparse point")
	}
	if file, err := CreatePrivateFile(root, "alias"); err == nil {
		file.Close()
		t.Fatal("exclusive private create followed a reparse point")
	}
	path, err := windows.UTF16PtrFromString(filepath.Join(root.Name(), "alias"))
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	alias := os.NewFile(uintptr(handle), "synthetic-alias")
	defer alias.Close()
	if CheckPrivate(alias) != ErrPrivateFile {
		t.Fatal("handle check accepted a reparse point")
	}
	original, err = OpenPrivateFile(root, "original")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	got, err := io.ReadAll(original)
	defer Clear(got)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("rejected alias operations changed the original")
	}
}

func TestPrivateWindowsRejectsBroadParent(t *testing.T) {
	root := privateTestRoot(t)
	path, err := windows.UTF16PtrFromString(root.Name())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	// Only this disposable fixture gets a NULL DACL, never a user directory.
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if file, err := CreatePrivateFile(root, "must-not-exist"); err != ErrPrivateFile {
		if file != nil {
			file.Close()
		}
		t.Fatal("permissive parent accepted")
	}
	if _, err := root.Stat("must-not-exist"); !os.IsNotExist(err) {
		t.Fatal("failed private create had side effects")
	}
	parent, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if CheckPrivate(parent) != ErrPrivateFile {
		t.Fatal("handle check accepted a NULL DACL")
	}
}
