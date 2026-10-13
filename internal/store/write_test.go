package store

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func testStash(path, key string, labels map[string]string, value []byte) error {
	return StashWithSecretsDir(filepath.Dir(path), path, key, labels, value)
}

func TestStashBashBytes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(storeTestdata, "stash-cases.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 5 {
			t.Fatal("bad stash catalog")
		}
		t.Run(fields[0], func(t *testing.T) {
			initial, err := os.ReadFile(filepath.Join(storeTestdata, "fixtures", fields[1]))
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "case.store")
			if err = os.WriteFile(path, initial, 0600); err != nil {
				t.Fatal(err)
			}
			labels := map[string]string{}
			if fields[3] != "" {
				for _, pair := range strings.Split(fields[3], ",") {
					name, value, ok := strings.Cut(pair, "=")
					if !ok {
						t.Fatal("invalid case labels")
					}
					labels[name] = value
				}
			}
			value := []byte(fields[4])
			value = bytes.ReplaceAll(value, []byte(`\n`), []byte{'\n'})
			if err = testStash(path, fields[2], labels, value); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(storeTestdata, "golden", "stash-"+fields[0]+".store"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("stash bytes differ from Bash golden (got %d bytes, want %d)", len(got), len(want))
			}
			if runtime.GOOS != "windows" {
				info, _ := os.Stat(path)
				if info.Mode().Perm() != 0600 {
					t.Error("replacement mode is not 0600")
				}
			} else {
				t.Log("Windows file ACLs do not expose Unix permission bits")
			}
		})
	}
}
func TestStashValidationAndTargets(t *testing.T) {
	for i, v := range []string{"", "\n", "space ", "\tlead", "bad\x00x", "bad\ry", "bad\ny\n", "'pair'", "\"pair\""} {
		t.Run(fmt.Sprintf("value-%d", i), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "item.store")
			err := testStash(path, "KEY", nil, []byte(v))
			if err == nil {
				t.Error("accepted invalid value")
			}
			if v != "" && err != nil && strings.Contains(err.Error(), v) {
				t.Error("value in diagnostic")
			}
			if _, e := os.Stat(path); !os.IsNotExist(e) {
				t.Error("invalid write created a file")
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "item.store")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := testStash(path, "KEY", nil, []byte("safe")); err == nil {
		t.Error("directory target accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, path); err == nil {
		if err := testStash(path, "KEY", nil, []byte("safe")); err == nil {
			t.Error("symlink target accepted")
		}
		linkedDir := filepath.Join(t.TempDir(), "linked")
		if err := os.Symlink(dir, linkedDir); err == nil {
			if err := testStash(filepath.Join(linkedDir, "new.store"), "KEY", nil, []byte("safe")); err == nil {
				t.Error("symlink secrets directory accepted")
			}
		}
	} else if runtime.GOOS == "windows" {
		t.Log("symlink creation unavailable without Windows developer privileges")
	}
}

// TestMain re-executes this binary for independent process writers.
func TestMain(m *testing.M) {
	mode := os.Getenv("GO_STORE_CHILD")
	if mode != "" {
		lockWait = 30 * time.Second
	}
	if mode == "" {
		os.Exit(m.Run())
	}
	path := os.Getenv("GO_STORE_PATH")
	if mode == "hold" {
		if err := withLock(filepath.Dir(path), 3*time.Second, func() error {
			// Pause after the same private file write as atomicReplace, before rename.
			scratch, err := os.MkdirTemp(filepath.Dir(path), ".secret-stash.")
			if err != nil {
				return err
			}
			defer os.RemoveAll(scratch)
			if err := os.WriteFile(filepath.Join(scratch, "owner"), []byte("secret-stash-v1\n"), 0600); err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(scratch, "replacement"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if _, err = f.Write([]byte("KEY=interrupted\n")); err != nil {
				_ = f.Close()
				return err
			}
			if err = f.Sync(); err != nil {
				_ = f.Close()
				return err
			}
			if err = f.Close(); err != nil {
				return err
			}
			fmt.Println("locked")
			time.Sleep(30 * time.Second)
			return nil
		}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if err := testStash(path, mode, nil, []byte("synthetic-"+mode)); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
func TestConcurrentStash(t *testing.T) {
	old := lockWait
	lockWait = 30 * time.Second
	defer func() { lockWait = old }()
	for _, subprocess := range []bool{false, true} {
		t.Run(fmt.Sprint("process-", subprocess), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "parallel.store")
			const n = 12
			var wg sync.WaitGroup
			errors := make(chan error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					key := fmt.Sprintf("KEY_%02d", i)
					if subprocess {
						cmd := exec.Command(os.Args[0])
						cmd.Env = append(os.Environ(), "GO_STORE_CHILD="+key, "GO_STORE_PATH="+path)
						if output, err := cmd.CombinedOutput(); err != nil {
							errors <- fmt.Errorf("child failed: %v (%s)", err, output)
						}
					} else {
						errors <- testStash(path, key, nil, []byte("synthetic-"+key))
					}
				}(i)
			}
			wg.Wait()
			close(errors)
			for err := range errors {
				if err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			records, warnings := Parse(data)
			if len(records) != n || len(warnings) != 0 {
				t.Fatalf("got %d records and %d warnings", len(records), len(warnings))
			}
			for _, r := range records {
				if string(r.Value) != "synthetic-"+r.Key {
					t.Error("lost or damaged assignment")
				}
			}
		})
	}
}
func TestKilledWriterLeavesLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows test runner does not provide POSIX process kill")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "item.store")
	original := []byte("KEY=prior\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "GO_STORE_CHILD=hold", "GO_STORE_PATH="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, 7)
	if _, err = stdout.Read(ready); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Error("interrupted writer changed the original file")
	}
	// As in Bash, SIGKILL cannot run cleanup; an owned lock is left for manual recovery.
	if _, err := os.Stat(filepath.Join(dir, ".write-lock", "token")); err != nil {
		t.Error("killed writer did not leave its ownership token")
	}
	if err := os.Remove(filepath.Join(dir, ".write-lock", "token")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ".write-lock")); err != nil {
		t.Fatal(err)
	}
	if err := testStash(path, "RECOVERED", nil, []byte("synthetic-recovery")); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".secret-stash.") || entry.Name() == ".write-lock" {
			t.Error("stale private directory or lock after recovery")
		}
	}
}
func FuzzStash(f *testing.F) {
	for _, v := range [][]byte{nil, []byte("raw"), []byte("edge'"), []byte("\"edge"), []byte("bad\nline"), []byte{0xff, 0xfe}, []byte("two\n\n")} {
		f.Add(v)
	}
	f.Fuzz(func(t *testing.T, value []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.store")
		err := testStash(path, "KEY", nil, value)
		normal, valid := NormalizeValue(value)
		if valid != nil {
			if err == nil {
				t.Error("invalid value accepted")
			}
			if err != nil && len(value) > 0 && bytes.Contains([]byte(err.Error()), value) {
				t.Error("value leaked")
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		records, _ := Parse(data)
		if len(records) != 1 || !bytes.Equal(records[0].Value, normal) {
			t.Error("stash round trip failed")
		}
	})
}

func TestExplicitStashWaitsForSecretsDirLock(t *testing.T) {
	base := t.TempDir()
	secrets := filepath.Join(base, "secrets")
	explicit := filepath.Join(base, "elsewhere", "file.store")
	t.Setenv("SECRETS_DIR", secrets)
	locked := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- WithWriteLock(secrets, func() error { close(locked); <-release; return nil })
	}()
	<-locked
	result := make(chan error, 1)
	go func() { result <- Stash(explicit, "KEY", nil, []byte("synthetic")) }()
	// Wait until the Go writer observes contention; it must not publish early.
	time.Sleep(150 * time.Millisecond)
	select {
	case err := <-result:
		t.Errorf("explicit stash bypassed secrets lock: %v", err)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(explicit); err != nil {
		t.Fatal(err)
	}
}

func TestWriteLockTimeout(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".write-lock"), 0700); err != nil {
		t.Fatal(err)
	}
	err := withLock(dir, 20*time.Millisecond, func() error { t.Error("acquired held lock"); return nil })
	if err == nil || !strings.Contains(err.Error(), "write lock timed out") {
		t.Fatalf("timeout = %v", err)
	}
}

func TestAnchoredReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store")
	if err := os.WriteFile(path, []byte("KEY=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink("store", filepath.Join(dir, "alias")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink privileges unavailable")
		}
		t.Fatal(err)
	}
	if _, err := readRegular(root, "alias"); err == nil {
		t.Error("followed symlinked store")
	}
	if _, err := ReadManifest(filepath.Join(dir, "alias"), "libsecret"); err == nil {
		t.Error("followed symlinked manifest")
	}
}

func TestStashProtectsSecretsDirectoryAndResetsTrailingScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix directory permissions")
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "labeled.store")
	if err := os.WriteFile(path, []byte("[env=dev]\n# keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := StashWithSecretsDir(dir, path, "KEY", nil, []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatalf("secrets directory mode: %v, %v", info, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "[env=dev]\n# keep\n[]\nKEY=synthetic\n" {
		t.Fatalf("unlabeled stash did not reset trailing scope: %v", err)
	}
}
