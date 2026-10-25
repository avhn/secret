package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// samePathIdentity compares opened objects, or equal missing suffixes beneath
// identical ancestors. An impossible operand has no identity; other lookup
// failures remain conservative. Keep this proof portable for injected tests.
func samePathIdentity(a, b string, stat func(string) (os.FileInfo, error), impossible func(error) bool) bool {
	for count := 0; count < 128; count++ {
		left, leftErr := stat(a)
		right, rightErr := stat(b)
		if impossible(leftErr) || impossible(rightErr) {
			return false
		}
		if leftErr == nil && rightErr == nil {
			return os.SameFile(left, right)
		}
		if leftErr != nil && !os.IsNotExist(leftErr) || rightErr != nil && !os.IsNotExist(rightErr) {
			return true
		}
		if leftErr == nil || rightErr == nil || !strings.EqualFold(filepath.Base(a), filepath.Base(b)) {
			return false
		}
		parentA, parentB := filepath.Dir(a), filepath.Dir(b)
		if parentA == a || parentB == b {
			return false
		}
		a, b = parentA, parentB
	}
	return true
}
