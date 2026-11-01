//go:build windows

package secure

import (
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

func TestStoreWindowsDescriptors(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, acl string
		valid     bool
	}{
		{"explicit trusted", "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;FA;;;BA)", true},
		{"inherited trusted", "D:(A;OICIID;FA;;;" + sid + ")(A;ID;FA;;;SY)(A;ID;FA;;;BA)", true},
		{"owner only", "D:P(A;;FA;;;" + sid + ")", true},
		{"empty", "D:P", false},
		{"everyone", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", false},
		{"users", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)", false},
		{"inherited outsider", "D:(A;;FA;;;" + sid + ")(A;ID;FR;;;BU)", false},
		{"authenticated users", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;AU)", false},
		{"custom group", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;S-1-5-21-111-222-333-1001)", false},
		{"inherit only outsider", "D:P(A;;FA;;;" + sid + ")(A;OICIIO;FR;;;WD)", false},
		{"deny", "D:P(D;;FW;;;WD)(A;;FA;;;" + sid + ")", false},
		{"conditional", "D:P(XA;;FA;;;" + sid + ";(@User.synthetic == 1))", false},
		{"object ACE", "D:P(OA;;FA;00112233-4455-6677-8899-aabbccddeeff;;" + sid + ")", false},
		{"AppContainer traverse only", "D:P(A;;FA;;;" + sid + ")(A;;FA;;;SY)(A;;0x100020;;;S-1-15-3-65536-1)", true},
		{"AppContainer read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;S-1-15-3-65536-1)", false},
		{"outsider traverse and read attributes", "D:P(A;;FA;;;" + sid + ")(A;;0x100080;;;WD)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + tc.acl)
			if err != nil {
				t.Fatal(err)
			}
			if got := checkStoreDescriptor(descriptor, user.User.Sid); (got == nil) != tc.valid {
				t.Fatalf("acceptance = %v, want %v", got == nil, tc.valid)
			}
		})
	}
	// Profile folders are commonly owned by SYSTEM or Administrators.
	for _, owner := range []string{"SY", "BA"} {
		trusted, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + sid + ")")
		if err != nil {
			t.Fatal(err)
		}
		if checkStoreDescriptor(trusted, user.User.Sid) != nil {
			t.Fatalf("trusted owner %s rejected", owner)
		}
	}
	wrong, err := windows.SecurityDescriptorFromString("O:BUD:P(A;;FA;;;" + sid + ")")
	if err != nil {
		t.Fatal(err)
	}
	if checkStoreDescriptor(wrong, user.User.Sid) == nil {
		t.Fatal("wrong owner accepted")
	}
	null, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	if err := null.SetOwner(user.User.Sid, false); err != nil {
		t.Fatal(err)
	}
	if err := null.SetDACL(nil, true, false); err != nil {
		t.Fatal(err)
	}
	if checkStoreDescriptor(null, user.User.Sid) == nil {
		t.Fatal("NULL DACL accepted")
	}
}

func TestStoreWindowsHandlePolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, acl string
		valid     bool
	}{
		{"trusted", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;SY)(A;;FA;;;BA)", true},
		{"NULL", "", false},
		{"empty", "D:P", false},
		{"everyone read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", false},
		{"users read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;BU)", false},
		{"authenticated read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;AU)", false},
		{"custom group read", "D:P(A;;FA;;;" + sid + ")(A;;FR;;;S-1-5-21-111-222-333-1001)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := privateTestRoot(t)
			file, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			name, err := windows.UTF16PtrFromString(root.Name())
			if err != nil {
				t.Fatal(err)
			}
			handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer windows.CloseHandle(handle)
			original, err := privateDescriptor(true)
			if err != nil {
				t.Fatal(err)
			}
			originalACL, _, err := original.DACL()
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, originalACL, nil); err != nil {
					t.Error(err)
				}
				runtime.KeepAlive(original)
			}()
			var descriptor *windows.SECURITY_DESCRIPTOR
			var acl *windows.ACL
			if tc.acl != "" {
				descriptor, err = windows.SecurityDescriptorFromString(tc.acl)
				if err != nil {
					t.Fatal(err)
				}
				acl, _, err = descriptor.DACL()
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			runtime.KeepAlive(descriptor)
			if got := CheckStoreDirectory(file); (got == nil) != tc.valid {
				t.Fatalf("handle acceptance = %v, want %v", got == nil, tc.valid)
			}
			if CheckPrivate(file) == nil {
				t.Fatal("strict directory check weakened")
			}
		})
	}
}

func TestStoreWindowsDirectoryIdentity(t *testing.T) {
	root := privateTestRoot(t)
	for _, name := range []string{"first", "second"} {
		if err := CreatePrivateDirectory(root, name); err != nil {
			t.Fatal(err)
		}
	}
	checked, err := checkedChild(root, "first", true, false, CheckPrivate, CheckStoreDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer checked.Close()
	if err := root.Rename("first", "old"); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("second", "first"); err != nil {
		t.Fatal(err)
	}
	if child, err := checkedDirectoryRoot(root, "first", checked, CheckStoreDirectory); err == nil {
		child.Close()
		t.Fatal("identity swap accepted")
	}
	if err := root.Symlink("old", "alias"); err != nil {
		t.Fatal(err)
	}
	if child, err := OpenStoreDirectory(root, "alias"); err == nil {
		child.Close()
		t.Fatal("reparse directory accepted")
	}
	file, err := CreatePrivateFile(root, "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if CheckStoreDirectory(file) == nil {
		t.Fatal("regular file accepted as directory")
	}
	if err := root.Symlink("regular", "file-alias"); err != nil {
		t.Fatal(err)
	}
	if alias, err := OpenStoreFile(root, "file-alias"); err == nil {
		alias.Close()
		t.Fatal("reparse file accepted")
	}
}

func TestStoreWindowsFileDescriptor(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for _, tc := range []struct {
		name, descriptor string
		valid            bool
	}{
		{"explicit owner only", "O:" + sid + "D:P(A;;FA;;;" + sid + ")", true},
		{"inherited owner only", "O:" + sid + "D:(A;ID;FA;;;" + sid + ")", true},
		{"inherited owner plus SYSTEM", "O:" + sid + "D:(A;ID;FA;;;" + sid + ")(A;ID;FA;;;SY)", false},
		{"owner plus everyone", "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", false},
		{"SYSTEM owner", "O:SYD:P(A;;FA;;;" + sid + ")", false},
		{"empty", "O:" + sid + "D:P", false},
		{"deny", "O:" + sid + "D:P(D;;FW;;;WD)(A;;FA;;;" + sid + ")", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(tc.descriptor)
			if err != nil {
				t.Fatal(err)
			}
			if got := checkStoreFileDescriptor(descriptor, user.User.Sid); (got == nil) != tc.valid {
				t.Fatalf("acceptance = %v, want %v", got == nil, tc.valid)
			}
		})
	}
}
