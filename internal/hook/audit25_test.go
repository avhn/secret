package hook

import "testing"

// Candidate commands are envelope data only; all metadata is synthetic.
func TestAudit25Envelopes(t *testing.T) {
	testAuditEnvelopes(t, "../../testdata/hook/audit25.json")
}
