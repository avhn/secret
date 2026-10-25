package backend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/store"
	"github.com/avhn/secret/internal/testutil"
)

func TestBackendFailureInventory(t *testing.T) {
	// Inventory keys are from testdata/inventory/backends.tsv.
	for _, tc := range []struct {
		inventory                     string
		putFail, getFail, publishFail bool
		wantOrphan                    bool
	}{
		{"put_failure/no_manifest", true, false, false, false},
		{"lookup_failure/no_published_record", false, true, false, true},
		{"manifest_failure/orphan_exists", false, false, true, true},
		{"failed_publish_existing/prior_record_intact", false, false, true, true},
	} {
		t.Run(tc.inventory, func(t *testing.T) {
			dir := testutil.TempDir(t)
			s := &stub{dir: filepath.Join(dir, "stub"), backend: "libsecret"}
			if err := os.MkdirAll(s.dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "other.keys")
			existing := tc.inventory == "failed_publish_existing/prior_record_intact"
			if existing {
				if err := Stash(dir, "libsecret:other", "PRIOR", nil, []byte("synthetic-prior"), s); err != nil {
					t.Fatal(err)
				}
			}
			s.putFail, s.getFail = tc.putFail, tc.getFail
			publish := store.UpdateManifest
			if tc.publishFail {
				publish = func(string, string, string, map[string]string, string) error {
					return errors.New("synthetic publish failure")
				}
			}
			err := stashWithPublish(dir, "libsecret:other", "NEW", nil, []byte("synthetic-new"), s, publish)
			if err == nil {
				t.Error("injected failure accepted")
			}
			records, readErr := store.ReadManifest(path, "libsecret")
			if existing {
				if readErr != nil || len(records) != 1 || records[0].Key != "PRIOR" {
					t.Error("prior inventory changed")
				}
			} else if !os.IsNotExist(readErr) {
				t.Error("failed write published a manifest")
			}
			items, _ := os.ReadDir(filepath.Join(s.dir, "libsecret", "secret", "other"))
			if (len(items) > 0) != tc.wantOrphan && !existing {
				t.Error("unexpected orphan state")
			}
			if existing && len(items) != 2 {
				t.Error("existing item or orphan missing")
			}
		})
	}
}
