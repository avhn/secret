//go:build windows

package backend

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// x/sys/windows has no CredMan wrappers. These declarations match wincred.h:
// CREDENTIALW, BOOL Cred{Read,Write,Delete}W and VOID CredFree(PVOID).
// All calls are synchronous and use only advapi32 from the system directory.
var (
	credDLL    = windows.NewLazySystemDLL("advapi32.dll")
	credRead   = credDLL.NewProc("CredReadW")
	credWrite  = credDLL.NewProc("CredWriteW")
	credDelete = credDLL.NewProc("CredDeleteW")
	credFree   = credDLL.NewProc("CredFree")
)

type nativeCredential struct {
	flags          uint32
	kind           uint32
	target         *uint16
	comment        *uint16
	lastWritten    windows.Filetime
	blobSize       uint32
	blob           *byte
	persist        uint32
	attributeCount uint32
	attributes     unsafe.Pointer
	targetAlias    *uint16
	userName       *uint16
}

type nativeWincred struct{}

func newWincred() (Provider, error) {
	for _, proc := range []*windows.LazyProc{credRead, credWrite, credDelete, credFree} {
		if proc.Find() != nil {
			return nil, ErrUnsupported
		}
	}
	return wincred{api: nativeWincred{}}, nil
}

// sameNativeTarget reads at most the requested UTF-16 target plus its terminator,
// stopping at an earlier NUL. No arbitrary provider string enters an error.
func sameNativeTarget(actual *uint16, expected []uint16) bool {
	if actual == nil {
		return false
	}
	for i, want := range expected {
		got := *(*uint16)(unsafe.Add(unsafe.Pointer(actual), uintptr(i)*2))
		if got != want {
			return false
		}
		if got == 0 {
			return i == len(expected)-1
		}
	}
	return false
}

func (nativeWincred) read(target string) (*wincredRecord, error) {
	wide, err := windows.UTF16FromString(target)
	if err != nil {
		return nil, errors.New("backend lookup failed")
	}
	var credential *nativeCredential
	ok, _, callErr := credRead.Call(uintptr(unsafe.Pointer(&wide[0])), wincredGeneric, 0, uintptr(unsafe.Pointer(&credential)))
	runtime.KeepAlive(wide)
	var record *wincredRecord
	if credential != nil {
		record = &wincredRecord{kind: credential.kind, size: credential.blobSize, release: func() {
			credFree.Call(uintptr(unsafe.Pointer(credential)))
		}}
		// Never construct an unbounded native slice. An impossible oversized
		// record is rejected; clear its bounded prefix before freeing it.
		if credential.blob != nil {
			size := min(credential.blobSize, uint32(wincredBlobLimit))
			record.blob = unsafe.Slice(credential.blob, int(size))
		}
		if sameNativeTarget(credential.target, wide) {
			record.target = target
		}
	}
	if ok == 0 {
		if callErr == windows.ERROR_NOT_FOUND {
			return record, errWincredMissing
		}
		return record, errors.New("backend lookup failed")
	}
	return record, nil
}

func (nativeWincred) write(target string, blob []byte) error {
	if len(blob) > wincredBlobLimit {
		return errors.New("backend put failed")
	}
	wide, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return errors.New("backend put failed")
	}
	credential := nativeCredential{kind: wincredGeneric, target: wide, blobSize: uint32(len(blob)), persist: wincredLocalMachine}
	if len(blob) != 0 {
		credential.blob = &blob[0]
	}
	ok, _, _ := credWrite.Call(uintptr(unsafe.Pointer(&credential)), 0)
	runtime.KeepAlive(credential)
	runtime.KeepAlive(blob)
	if ok == 0 {
		return errors.New("backend put failed")
	}
	return nil
}

func (nativeWincred) delete(target string) error {
	wide, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return errors.New("backend delete failed")
	}
	ok, _, callErr := credDelete.Call(uintptr(unsafe.Pointer(wide)), wincredGeneric, 0)
	runtime.KeepAlive(wide)
	if ok == 0 {
		if callErr == windows.ERROR_NOT_FOUND {
			return errWincredMissing
		}
		return errors.New("backend delete failed")
	}
	return nil
}
