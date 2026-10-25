package feature

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

func auditTestEvent() store.AuditEvent {
	return store.AuditEvent{Version: store.MetadataVersion, Time: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), Action: store.ActionRotate, Target: "libsecret:synthetic", Keys: []string{"TOKEN"}, Labels: map[string]string{"env": "prod"}, Outcome: store.AuditSuccess}
}

func auditTestDirectory(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Unix private audit persistence")
	}
	// Stock macOS temporary roots can have a system /var alias. Fixtures use the
	// physical disposable directory, not an exception to production alias checks.
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "audit")
}

func auditTestLog(t *testing.T, maxBytes, maxFiles int) *AuditLog {
	t.Helper()
	log, err := OpenAudit(AuditConfig{Enabled: true, Directory: auditTestDirectory(t), MaxBytes: maxBytes, MaxFiles: maxFiles})
	if err != nil {
		t.Fatal(err)
	}
	return log
}

func TestAuditDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "must-not-be-created")
	log, err := OpenAudit(AuditConfig{Directory: path, MaxBytes: -1, MaxFiles: -1})
	if err != nil || log == nil {
		t.Fatal("disabled audit rejected irrelevant configuration")
	}
	if err := log.Record(store.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	if err := (*AuditLog)(nil).Record(store.AuditEvent{}); err != nil {
		t.Fatal(err)
	}
	result, err := log.Query(AuditQuery{})
	if err != nil || result.Version != 1 || len(result.Events) != 0 {
		t.Fatal("disabled audit query")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("disabled audit touched filesystem")
	}

}

func TestAuditSchemaGolden(t *testing.T) {
	log := auditTestLog(t, 0, 0)
	event := auditTestEvent()
	if err := log.Record(event); err != nil {
		t.Fatal(err)
	}
	// Record does not retain mutable slices or maps.
	event.Keys[0], event.Labels["env"] = "CHANGED", "dev"
	result, err := log.Query(AuditQuery{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "feature", "audit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(got, '\n'), want) {
		t.Fatalf("audit schema differs:\n%s", got)
	}
	for _, name := range []string{"audit.jsonl", "."} {
		info, err := os.Lstat(filepath.Join(log.config.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if name == "." {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatal("insecure audit mode")
		}
	}
	data, err := os.ReadFile(filepath.Join(log.config.Directory, auditName(0)))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"value", "argv", "stderr", "error", "digest", "length"} {
		if bytes.Contains(data, []byte(`"`+field+`"`)) {
			t.Fatalf("forbidden audit field %s", field)
		}
	}
}

func TestAuditRotationAndQuery(t *testing.T) {
	log := auditTestLog(t, 512, 3)
	for index := 0; index < 12; index++ {
		event := auditTestEvent()
		event.Time = event.Time.Add(time.Duration(index) * time.Minute)
		if index%2 != 0 {
			event.Action, event.Outcome, event.Keys = store.ActionDelete, store.AuditFailure, []string{"OTHER"}
		}
		if err := log.Record(event); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(log.config.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("rotation retained %d files", len(entries))
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || info.Size() > 512 || info.Mode().Perm() != 0600 {
			t.Fatal("rotation exceeded bounds or mode")
		}
	}
	all, err := log.Query(AuditQuery{})
	if err != nil || len(all.Events) != 9 {
		t.Fatalf("rotated query: %v, %d events", err, len(all.Events))
	}
	for index := 1; index < len(all.Events); index++ {
		if !all.Events[index-1].Time.Before(all.Events[index].Time) {
			t.Fatal("rotation order")
		}
	}
	last, err := log.Query(AuditQuery{Limit: 2})
	if err != nil || !reflect.DeepEqual(last.Events, all.Events[len(all.Events)-2:]) {
		t.Fatal("query limit lost recent events")
	}
	base := auditTestEvent().Time
	filtered, err := log.Query(AuditQuery{Action: store.ActionDelete, Target: "libsecret:synthetic", Key: "OTHER", Outcome: store.AuditFailure, Since: base.Add(9 * time.Minute), Until: base.Add(11 * time.Minute)})
	if err != nil || len(filtered.Events) != 2 {
		t.Fatalf("query filtering: %v, %d events", err, len(filtered.Events))
	}
	none, err := log.Query(AuditQuery{Key: "MISSING"})
	if err != nil || len(none.Events) != 0 {
		t.Fatal("key filter")
	}
	for _, query := range []AuditQuery{{Action: "run"}, {Outcome: "synthetic-stderr-sentinel"}, {Key: "bad-key"}, {Target: "relative"}, {Limit: -1}, {Limit: 10001}, {Since: base.Add(time.Hour), Until: base}} {
		if _, err := log.Query(query); !errors.Is(err, secure.ErrAudit) {
			t.Fatal("invalid audit query accepted")
		}
	}
	// A one-file ring has no numbered backup.
	single := auditTestLog(t, 256, 1)
	for index := 0; index < 3; index++ {
		if err := single.Record(auditTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	if entries, err := os.ReadDir(single.config.Directory); err != nil || len(entries) != 1 {
		t.Fatal("one-file rotation")
	}
}

func TestAuditPermissionsAliasesAndLock(t *testing.T) {
	for _, scenario := range []string{"directory mode", "directory symlink", "ancestor symlink", "file mode", "file symlink", "rotated symlink", "nonregular", "oversize", "lock"} {
		t.Run(scenario, func(t *testing.T) {
			log := auditTestLog(t, 512, 3)
			if err := log.Record(auditTestEvent()); err != nil {
				t.Fatal(err)
			}
			dir := log.config.Directory
			target := filepath.Join(filepath.Dir(dir), "untouched")
			if err := os.WriteFile(target, []byte("synthetic-provider-stderr-sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "directory mode":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory symlink":
				if err := os.Rename(dir, dir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-original", dir); err != nil {
					t.Fatal(err)
				}
			case "ancestor symlink":
				alias := filepath.Join(filepath.Dir(dir), "alias")
				if err := os.Symlink(filepath.Dir(dir), alias); err != nil {
					t.Fatal(err)
				}
				log.config.Directory = filepath.Join(alias, "audit")
			case "file mode":
				if err := os.Chmod(filepath.Join(dir, auditName(0)), 0644); err != nil {
					t.Fatal(err)
				}
			case "file symlink", "rotated symlink":
				name := auditName(0)
				if scenario == "rotated symlink" {
					name = auditName(2)
				} else if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			case "nonregular":
				if err := os.Mkdir(filepath.Join(dir, auditName(1)), 0700); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(filepath.Join(dir, auditName(1)), bytes.Repeat([]byte{'x'}, 513), 0600); err != nil {
					t.Fatal(err)
				}
			case "lock":
				if err := os.Mkdir(filepath.Join(dir, ".audit-lock"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := log.Record(auditTestEvent()); !errors.Is(err, secure.ErrAudit) {
				t.Fatal("unsafe audit write accepted")
			}
			if _, err := log.Query(AuditQuery{}); !errors.Is(err, secure.ErrAudit) {
				t.Fatal("unsafe audit query accepted")
			}
			body, err := os.ReadFile(target)
			if err != nil || string(body) != "synthetic-provider-stderr-sentinel" {
				t.Fatal("audit modified symlink target")
			}
		})
	}
}

func TestAuditValidationAndConcurrency(t *testing.T) {
	log := auditTestLog(t, 0, 0)
	for _, mutate := range []func(*store.AuditEvent){
		func(e *store.AuditEvent) { e.Version = 2 }, func(e *store.AuditEvent) { e.Action = "run synthetic-child-argv-sentinel" },
		func(e *store.AuditEvent) { e.Outcome = "synthetic-provider-stderr-sentinel" }, func(e *store.AuditEvent) { e.Target = "relative" },
		func(e *store.AuditEvent) { e.Target = "file:relative" }, func(e *store.AuditEvent) { e.Keys = []string{"bad-key"} },
		func(e *store.AuditEvent) { e.Keys = nil }, func(e *store.AuditEvent) { e.Labels["bad-name"] = "prod" },
		func(e *store.AuditEvent) { e.Time = time.Time{} }, func(e *store.AuditEvent) { e.Source = "op:unsafe/reference" },
		func(e *store.AuditEvent) { e.Keys = []string{strings.Repeat("K", 257)} },
		func(e *store.AuditEvent) {
			e.Keys = make([]string, 1024)
			for i := range e.Keys {
				e.Keys[i] = strings.Repeat("K", 256)
			}
		},
	} {
		event := auditTestEvent()
		mutate(&event)
		if err := log.Record(event); !errors.Is(err, secure.ErrAudit) {
			t.Fatal("invalid event accepted")
		}
	}
	for _, source := range []string{"op:synthetic-item", "bw:synthetic-item", "dotenv:" + filepath.Join(filepath.Dir(log.config.Directory), "synthetic.env")} {
		event := auditTestEvent()
		event.Action, event.Source = store.ActionImport, source
		if err := log.Record(event); err != nil {
			t.Fatal(err)
		}
	}
	var group sync.WaitGroup
	for index := 0; index < 12; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := log.Record(auditTestEvent()); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	result, err := log.Query(AuditQuery{})
	if err != nil || len(result.Events) != 15 {
		t.Fatal("concurrent records lost")
	}
}

func TestAuditConfigurationBounds(t *testing.T) {
	directory := auditTestDirectory(t)
	for _, config := range []AuditConfig{
		{Enabled: true},
		{Enabled: true, Directory: "relative"},
		{Enabled: true, Directory: directory, MaxBytes: 255},
		{Enabled: true, Directory: directory, MaxBytes: maxAuditFileBytes + 1},
		{Enabled: true, Directory: directory, MaxFiles: -1},
		{Enabled: true, Directory: directory, MaxFiles: maxAuditFiles + 1},
	} {
		if _, err := OpenAudit(config); !errors.Is(err, secure.ErrAudit) {
			t.Fatal("invalid persistence bound accepted")
		}
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("invalid configuration created audit directory")
	}
	log, err := OpenAudit(AuditConfig{Enabled: true, Directory: directory, MaxBytes: 256, MaxFiles: 3})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if err := log.Record(auditTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := OpenAudit(AuditConfig{Enabled: true, Directory: directory, MaxBytes: 256, MaxFiles: 1}); !errors.Is(err, secure.ErrAudit) {
		t.Fatal("smaller retention silently left old managed files")
	}
	before, err := os.ReadFile(filepath.Join(directory, auditName(0)))
	if err != nil {
		t.Fatal(err)
	}
	event := auditTestEvent()
	event.Keys = []string{strings.Repeat("K", 256)}
	if err := log.Record(event); !errors.Is(err, secure.ErrAudit) {
		t.Fatal("event exceeding file bound accepted")
	}
	after, err := os.ReadFile(filepath.Join(directory, auditName(0)))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected event changed persisted audit")
	}
}

func TestAuditRejectsMalformedPersistedRecords(t *testing.T) {
	for _, body := range []string{"synthetic-secret-not-a-record\n", `{}`, `{"version":1,"version":2}` + "\n", `{"value":"synthetic-raw-value","argv":"synthetic-child-argv","stderr":"synthetic-provider-stderr"}` + "\n"} {
		log := auditTestLog(t, 0, 0)
		if err := os.WriteFile(filepath.Join(log.config.Directory, auditName(0)), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if err := log.Record(auditTestEvent()); !errors.Is(err, secure.ErrAudit) {
			t.Fatal("appended to malformed log")
		}
		if _, err := log.Query(AuditQuery{}); !errors.Is(err, secure.ErrAudit) {
			t.Fatal("returned malformed log")
		}
	}
}
