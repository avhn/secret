package secure

import (
	"errors"
	"path/filepath"
)

var (
	ErrPrivateFile = errors.New("private filesystem operation failed")
	ErrPrivateBusy = errors.New("private filesystem object temporarily busy")
)

// Keep native relative opens to one unambiguous component. os.Root remains the
// caller's directory anchor; these helpers never reopen root.Name() by path.
func privateChildName(name string) bool {
	return name != "." && filepath.IsLocal(name) && filepath.Base(name) == name && ValidateStorePath(name) == nil
}
