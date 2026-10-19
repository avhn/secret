// Package secure defines best-effort byte cleanup and fixed operator errors.
// Values stay in owned []byte buffers, never errors, logs, argv or JSON. Cleanup
// cannot erase runtime copies, swapped pages or crash leftovers.
package secure

import (
	"errors"
	"runtime"
)

// Fixed errors are safe to return across operator and provider boundaries. Never
// wrap an underlying provider, terminal or parser error that may contain values.
var (
	ErrTerminalRequired = errors.New("operator requires stdin and stdout terminals")
	ErrTerminal         = errors.New("operator controlling terminal unavailable")
	ErrConsent          = errors.New("operator confirmation declined")
	ErrInput            = errors.New("operator hidden input failed")
	ErrInvalidRequest   = errors.New("invalid operator request")
	ErrUnsupported      = errors.New("operator not supported on this platform")
	ErrTransaction      = errors.New("operator transaction failed")
	ErrConflict         = errors.New("operator destination conflict")
	ErrNotFound         = errors.New("operator key is not set")
	ErrRecovery         = errors.New("operator recovery requires manual verification")
	ErrAudit            = errors.New("operator audit failed")
)

// Clone returns an independent owned copy of borrowed bytes. The caller must
// Clear the result when finished; the source remains its original owner's duty.
func Clone(value []byte) []byte {
	if value == nil {
		return nil
	}
	result := make([]byte, len(value))
	copy(result, value)
	return result
}

// Clear zeros the entire accessible backing allocation, including bytes past len
// up to cap. Only pass owned buffers, not subslices of another owner's allocation.
// It is safe on nil and repeated calls, but is not a secure-erasure guarantee.
func Clear(value []byte) {
	clear(value[:cap(value)])
	runtime.KeepAlive(value)
}
