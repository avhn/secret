//go:build windows

package secure

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FILE_ALL_ACCESS from WinNT.h: STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1ff.
const fileAllAccess windows.ACCESS_MASK = 0x001f01ff

// CheckPrivate inspects the opened object, not its path or Unix mode bits. The
// deliberately narrow ACL contract is a protected DACL granting only the current
// process user full access. Administrators and the same user are not isolated.
func CheckPrivate(file *os.File) error {
	return checkFileDescriptor(file, false, checkPrivateDescriptor)
}

// CheckStoreDirectory accepts an owned store parent with only user, SYSTEM and
// Administrators allow ACEs. It never repairs permissions. Files remain private.
func CheckStoreDirectory(file *os.File) error {
	return checkFileDescriptor(file, true, checkStoreDescriptor)
}

func checkFileDescriptor(file *os.File, directory bool, check func(*windows.SECURITY_DESCRIPTOR, *windows.SID) error) error {
	if file == nil {
		return ErrPrivateFile
	}
	var info windows.ByHandleFileInformation
	handle := windows.Handle(file.Fd())
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrPrivateFile
	}
	if directory && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrPrivateFile
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrPrivateFile
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || check(descriptor, user.User.Sid) != nil {
		return ErrPrivateFile
	}
	runtime.KeepAlive(file)
	return nil
}

func checkPrivateDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if descriptor == nil || !descriptor.IsValid() || user == nil {
		return ErrPrivateFile
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return ErrPrivateFile
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrPrivateFile
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount != 1 {
		return ErrPrivateFile
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if windows.GetAce(acl, 0, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != fileAllAccess || ace.Header.AceFlags & ^uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0 {
		return ErrPrivateFile
	}
	// GetSecurityInfo returns a validated, self-relative descriptor owned by Go.
	// The variable-sized SID begins at SidStart, not after the ACE structure.
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !sid.IsValid() || !sid.Equals(user) {
		return ErrPrivateFile
	}
	runtime.KeepAlive(descriptor)
	return nil
}

// Only ordinary allow ACEs are supported. Inheritance affects propagation, not
// the principal allowlist; deny, object-specific and conditional ACEs fail closed.
func checkStoreDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if descriptor == nil || !descriptor.IsValid() || user == nil {
		return ErrPrivateFile
	}
	owner, _, err := descriptor.Owner()
	// Windows profile folders are commonly owned by SYSTEM or Administrators.
	if err != nil || owner == nil || (!owner.Equals(user) && !owner.IsWellKnown(windows.WinLocalSystemSid) && !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return ErrPrivateFile
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrPrivateFile
	}
	// Other principals (for example AppContainer capability SIDs on profiles)
	// may only traverse: they can neither list, read nor change the folder.
	const traverseOnly = windows.FILE_TRAVERSE | windows.SYNCHRONIZE
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags & ^uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.NO_PROPAGATE_INHERIT_ACE|windows.INHERIT_ONLY_ACE|windows.INHERITED_ACE) != 0 {
			return ErrPrivateFile
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return ErrPrivateFile
		}
		trusted := sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
		if !trusted && uint32(ace.Mask)&^uint32(traverseOnly) != 0 {
			return ErrPrivateFile
		}
	}
	runtime.KeepAlive(descriptor)
	return nil
}

func privateDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, ErrPrivateFile
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sid := user.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + inherit + ";FA;;;" + sid + ")")
	if err != nil {
		return nil, ErrPrivateFile
	}
	return descriptor, nil
}

// CreatePrivateDirectory creates exactly one child with its final DACL present
// from creation. The parent may be public (for example the profile directory).
// Existing objects are never opened for repair or silently accepted.
func CreatePrivateDirectory(root *os.Root, name string) error {
	file, err := privateChild(root, name, true, true)
	if err != nil {
		return err
	}
	if file.Close() != nil {
		return ErrPrivateFile
	}
	return nil
}

// CreatePrivateFile exclusively creates an empty regular file beneath a verified
// private parent. It verifies the new handle before the caller can write bytes.
func CreatePrivateFile(root *os.Root, name string) (*os.File, error) {
	return privateChild(root, name, false, true)
}

// OpenPrivateFile opens an existing private regular file for reading, refusing
// final reparse points. Callers retain their os.Root anchor throughout the open.
func OpenPrivateFile(root *os.Root, name string) (*os.File, error) {
	return privateChild(root, name, false, false)
}

// OpenStoreFile reads an owner-only file beneath a trusted store parent.
func OpenStoreFile(root *os.Root, name string) (*os.File, error) {
	return checkedChild(root, name, false, false, CheckStoreDirectory, CheckStoreFile)
}

// CheckStoreFile accepts a store file owned by the current user whose DACL
// grants access only to that user. Entries may be explicit or inherited (a
// file created inside a private ~/.secrets folder inherits its single entry);
// any other principal, deny, object or conditional entry fails closed.
func CheckStoreFile(file *os.File) error {
	return checkFileDescriptor(file, false, checkStoreFileDescriptor)
}

func checkStoreFileDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	if descriptor == nil || !descriptor.IsValid() || user == nil {
		return ErrPrivateFile
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(user) {
		return ErrPrivateFile
	}
	acl, _, err := descriptor.DACL()
	if err != nil || acl == nil || acl.AceCount == 0 {
		return ErrPrivateFile
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags & ^uint8(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.NO_PROPAGATE_INHERIT_ACE|windows.INHERIT_ONLY_ACE|windows.INHERITED_ACE) != 0 {
			return ErrPrivateFile
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() || !sid.Equals(user) {
			return ErrPrivateFile
		}
	}
	runtime.KeepAlive(descriptor)
	return nil
}

// OpenStoreDirectory retains the same no-follow identity checks as private roots.
func OpenStoreDirectory(root *os.Root, name string) (*os.Root, error) {
	return openCheckedDirectory(root, name, CheckStoreDirectory)
}

// OpenPrivateDirectory retains an os.Root anchor and verifies that its handle
// identifies the same no-follow, ACL-checked directory. Never reopen root.Name().
func OpenPrivateDirectory(root *os.Root, name string) (*os.Root, error) {
	return openCheckedDirectory(root, name, CheckPrivate)
}

func openCheckedDirectory(root *os.Root, name string, check func(*os.File) error) (*os.Root, error) {
	file, err := checkedChild(root, name, true, false, CheckPrivate, check)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return checkedDirectoryRoot(root, name, file, check)
}

func checkedDirectoryRoot(root *os.Root, name string, file *os.File, check func(*os.File) error) (*os.Root, error) {
	before, err := file.Stat()
	if err != nil {
		return nil, ErrPrivateFile
	}
	child, err := root.OpenRoot(name)
	if err != nil {
		return nil, ErrPrivateFile
	}
	opened, err := child.Open(".")
	if err == nil {
		defer opened.Close()
		after, statErr := opened.Stat()
		if statErr == nil && os.SameFile(before, after) && check(opened) == nil {
			return child, nil
		}
	}
	child.Close()
	return nil, ErrPrivateFile
}

func privateChild(root *os.Root, name string, directory, create bool) (*os.File, error) {
	return checkedChild(root, name, directory, create, CheckPrivate, CheckPrivate)
}

func checkedChild(root *os.Root, name string, directory, create bool, checkParent, checkObject func(*os.File) error) (*os.File, error) {
	if root == nil || !privateChildName(name) {
		return nil, ErrPrivateFile
	}
	parent, err := root.Open(".")
	if err != nil {
		return nil, ErrPrivateFile
	}
	defer parent.Close()
	if !directory && checkParent(parent) != nil {
		return nil, ErrPrivateFile
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, ErrPrivateFile
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(parent.Fd()), ObjectName: objectName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	disposition := uint32(windows.FILE_OPEN)
	access := uint32(windows.FILE_GENERIC_READ)
	options := uint32(windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_NON_DIRECTORY_FILE)
	if directory {
		options = windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_DIRECTORY_FILE
	}
	if create {
		attributes.SecurityDescriptor, err = privateDescriptor(directory)
		if err != nil {
			return nil, err
		}
		disposition = windows.FILE_CREATE
		access |= windows.FILE_GENERIC_WRITE
	}
	var handle windows.Handle
	err = windows.NtCreateFile(&handle, access, &attributes, &windows.IO_STATUS_BLOCK{}, nil,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		disposition, options, 0, 0)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(parent)
	if err != nil {
		return nil, privateNativeError(err)
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrPrivateFile
	}
	if checkObject(file) != nil {
		file.Close()
		return nil, ErrPrivateFile
	}
	return file, nil
}

// Preserve only bounded classifications needed by lock/read callers. Permanent
// access denial is not delete-pending contention and must never be retried as it.
func privateNativeError(err error) error {
	switch err {
	case windows.STATUS_OBJECT_NAME_COLLISION:
		return os.ErrExist
	case windows.STATUS_OBJECT_NAME_NOT_FOUND, windows.STATUS_OBJECT_PATH_NOT_FOUND:
		return os.ErrNotExist
	case windows.STATUS_DELETE_PENDING, windows.STATUS_SHARING_VIOLATION:
		return ErrPrivateBusy
	default:
		return ErrPrivateFile
	}
}
