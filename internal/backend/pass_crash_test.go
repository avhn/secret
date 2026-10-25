package backend

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

// This child injects only the synthetic in-memory/file transport, never native
// pass or GPG. Checkpoints let the parent kill a real lock-owning process.
func TestPassCrashChild(t *testing.T) {
	root := os.Getenv("GO_PASS_CRASH_ROOT")
	if root == "" {
		return
	}
	fake := &passFake{directory: filepath.Join(root, "provider")}
	provider := &passProvider{directory: fake.directory, run: fake.run}
	provider.once.Do(func() {})
	err := (Transaction{SecretsDir: filepath.Join(root, "stores"), Reference: "pass:crash", Provider: provider}).apply(
		[]store.Mutation{{Kind: store.MutationPut, Key: "TOKEN", Value: []byte("synthetic-crash-new")}},
		transactionSteps{checkpoint: func(phase string, _ int) error {
			if phase == os.Getenv("GO_PASS_CRASH_PHASE") {
				fmt.Println("ready")
				<-time.After(30 * time.Second)
			}
			return nil
		}})
	if err != nil {
		t.Fatal(err)
	}
}
func TestPassKilledWriterKeepsRecovery(t *testing.T) {
	transactionPlatform(t)
	for _, phase := range []string{"prepare", "verify", "publish", "published", "cleanup", "complete"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			passwords := filepath.Join(root, "provider")
			dir := filepath.Join(root, "stores")
			if err := os.Mkdir(passwords, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(passwords, ".gpg-id"), []byte("synthetic-recipient\n"), 0600); err != nil {
				t.Fatal(err)
			}
			fake := &passFake{directory: passwords}
			provider := &passProvider{directory: passwords, run: fake.run}
			provider.once.Do(func() {})
			if err := Stash(dir, "pass:crash", "TOKEN", nil, []byte("synthetic-crash-prior"), provider); err != nil {
				t.Fatal(err)
			}
			path, _ := store.ManifestPath(dir, "pass:crash")
			prior, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestPassCrashChild$")
			cmd.Env = append(os.Environ(), "GO_PASS_CRASH_ROOT="+root, "GO_PASS_CRASH_PHASE="+phase)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			ready := make(chan bool, 1)
			go func() { scanner := bufio.NewScanner(stdout); ready <- scanner.Scan() && scanner.Text() == "ready" }()
			select {
			case ok := <-ready:
				if !ok {
					t.Fatal("synthetic crash child missed checkpoint")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("synthetic crash child timed out")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			published := phase == "published" || phase == "cleanup" || phase == "complete"
			if bytes.Equal(current, prior) == published {
				t.Fatal("pass crash crossed publication boundary")
			}
			token := filepath.Join(dir, ".write-lock", "token")
			owner, err := os.ReadFile(token)
			if err != nil || len(owner) != 33 {
				t.Fatal("killed pass writer lost tokened lock")
			}
			intent, err := store.ReadRecovery(path, "pass")
			if err != nil || len(intent.Prepared) != 1 || len(intent.Obsolete) != 1 {
				t.Fatal("pass crash lost recovery candidates")
			}
			data, err := os.ReadFile(path + ".recovery")
			if err != nil || bytes.Contains(data, []byte("synthetic-crash-")) {
				t.Fatal("recovery contains value bytes")
			}
			// Explicit test-only cleanup models manual owner verification. Production
			// never steals the lock or automatically clears recovery after a crash.
			if err := os.Remove(token); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Dir(token)); err != nil {
				t.Fatal(err)
			}
			calls := len(fake.calls)
			if err := (Transaction{SecretsDir: dir, Reference: "pass:crash", Provider: provider}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: "OTHER", Value: []byte("synthetic")}}); err != secure.ErrRecovery || len(fake.calls) != calls {
				t.Fatal("manual lock removal bypassed pass recovery")
			}
		})
	}
}
