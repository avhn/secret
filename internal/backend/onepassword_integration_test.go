package backend

import (
	"os"
	"testing"
)

// This required-provider gate is intentionally inactive, including in CI. It
// cannot be mistaken for provider evidence and never invokes an installed op.
// Replace the blocking result only after owner provisioning and licensing review,
// with a sanitized identity fixture from the exact pinned CLI release.
func TestOnePasswordIntegration(t *testing.T) {
	if os.Getenv("SECRET_REQUIRE_ONEPASSWORD") != "1" {
		t.Skip("isolated real-provider evidence and licensing review not provisioned")
	}
	t.Fatal("onepassword integration blocked: dispatch disabled pending licensing review, pinned whoami evidence and owner-provisioned isolated provider orchestration")
}
