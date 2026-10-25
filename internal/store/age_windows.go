package store

import (
	"os"
	"time"

	"github.com/avhn/secret/internal/secure"
)

func privateAgeInfo(os.FileInfo, bool) bool { return false }

// Age persistence remains unsupported until its native durability contract is tested.
func withRootLock(*os.Root, time.Duration, func(*os.Root) error) error { return secure.ErrUnsupported }
func atomicReplaceChecked(*os.Root, string, []byte, bool, func(string) error) error {
	return secure.ErrUnsupported
}
