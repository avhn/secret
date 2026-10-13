//go:build !secretstub

package backend

// Production builds never inspect SECRET_BACKEND_STUB_DIR.
func testProvider(string) Provider      { return nil }
func stubPublishFailure(Provider) error { return nil }
