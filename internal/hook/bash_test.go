package hook

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/avhn/secret/internal/hook/input"
)

// Unix shell-policy expectations remain unchanged. Native Windows has a separate
// fixed all-shell-deny contract, exercised by TestWindowsShellRequestsDeny and
// TestWindowsShellCorpusDeny rather than borrowing Bash allow controls.
func requireBashAnalysis(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix Bash adapter contract; Windows shell requests always deny")
	}
}

func requireBashEnvelope(t *testing.T, data []byte) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	if envelope, err := input.Decode(bytes.NewReader(data)); err == nil && envelope.Tool == "Bash" {
		requireBashAnalysis(t)
	}
}
