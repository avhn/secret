package hook

import "testing"

// Candidate launches are envelope data only; metadata and HOME are disposable.
func TestAudit25LaunchEnvelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit25-launch.json")
}
