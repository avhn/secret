//go:build windows

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/testutil"
	"golang.org/x/sys/windows"
)

// Changing HOME or setting the gate alone does not isolate the clipboard. Require
// a disposable GitHub-hosted Windows runner as well as the explicit test gate.
func requireClipboardCI(t *testing.T) {
	t.Helper()
	if os.Getenv("SECRET_REQUIRE_WINDOWS_CLIPBOARD") != "1" {
		t.Skip("disposable hosted Windows clipboard CI only")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || !filepath.IsAbs(os.Getenv("RUNNER_TEMP")) {
		t.Fatal("clipboard integration requires a disposable GitHub-hosted Windows runner")
	}
}

// Preserve any pre-existing clipboard without reading it: the first mutation
// requires an empty clipboard, checked while OpenClipboard excludes other writers.
// All later contents in this test are disposable synthetic data. Do not parallelize.
type disposableClipboard struct {
	nativeClipboard
	first bool
}

// Called only inside withOpen, on its locked thread. Zero formats and API
// failure both return zero; clear last-error first so failure cannot authorize
// replacing pre-existing clipboard data.
func nativeClipboardEmpty() (bool, error) {
	countFormats := clipboardUser32.NewProc("CountClipboardFormats")
	if countFormats.Find() != nil {
		return false, errClipboard
	}
	clipboardKernel.NewProc("SetLastError").Call(0)
	count, _, err := countFormats.Call()
	if count == 0 && err != windows.ERROR_SUCCESS {
		return false, errClipboard
	}
	return count == 0, nil
}

func (c *disposableClipboard) empty() error {
	if c.first {
		empty, err := nativeClipboardEmpty()
		if err != nil || !empty {
			return errClipboard
		}
		c.first = false
	}
	return c.nativeClipboard.empty()
}

func TestWindowsClipboardIntegration(t *testing.T) {
	requireClipboardCI(t)
	api := &disposableClipboard{first: true}
	c := windowsClipboard{api: api, sleep: time.Sleep}
	value := []byte("synthetic-clipboard-\U0001f510")
	replacement := []byte("synthetic-replacement")
	t.Cleanup(func() {
		defer secure.Clear(value)
		defer secure.Clear(replacement)
		if api.first {
			return // No mutation was authorized; do not inspect existing contents.
		}
		// Missing CF_UNICODETEXT after a successful empty is expected. Attempt
		// both known disposable values, then check the final format count.
		_ = c.clearIfUnchanged(value)
		_ = c.clearIfUnchanged(replacement)
		if err := c.withOpen(func() error {
			empty, err := nativeClipboardEmpty()
			if err != nil || !empty {
				return errClipboard
			}
			return nil
		}); err != nil {
			t.Error("disposable clipboard cleanup did not leave the initially empty clipboard empty")
		}
	})
	if c.copy(value) != nil {
		t.Fatal("disposable clipboard initialization failed (clipboard must initially be empty)")
	}
	if err := c.withOpen(func() error {
		want, _ := clipboardUTF16(value)
		defer secure.Clear(want)
		got, err := api.data(clipboardUnicodeText, len(want))
		defer secure.Clear(got)
		if err != nil || !bytes.Equal(got, want) {
			return errClipboard
		}
		for _, name := range []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"} {
			format, err := api.register(name)
			if err != nil {
				return errClipboard
			}
			data, err := api.data(format, 4)
			matches := bytes.Equal(data, []byte{0, 0, 0, 0})
			secure.Clear(data)
			if err != nil || !matches {
				return errClipboard
			}
		}
		return nil
	}); err != nil {
		t.Fatal("native Unicode text or exclusion format round trip failed")
	}
	if c.copy(replacement) != nil || c.clearIfUnchanged(value) != nil {
		t.Fatal("native changed-value clear failed")
	}
	assertNativeClipboard(t, c, replacement)
	if c.clearIfUnchanged(replacement) != nil {
		t.Fatal("native unchanged-value clear failed")
	}

	// Build the real CLI only inside this gated test. Its detached clearer must
	// outlive clip, not hold CombinedOutput pipes open, and retain conditional
	// clearing when another value replaces the original before the timeout.
	dir := testutil.TempDir(t)
	binary := filepath.Join(dir, "secret.exe")
	build := exec.Command("go", "build", "-o", binary, "./cmd/secret")
	build.Dir = filepath.Join("..", "..")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("synthetic CLI build failed: %s", output)
	}
	storePath := filepath.Join(dir, "synthetic.store")
	if err := testutil.WriteFile(storePath, []byte("TOKEN=synthetic-clipboard-value\n"), 0600); err != nil {
		t.Fatal("synthetic store setup failed")
	}
	cliValue := []byte("synthetic-clipboard-value")
	t.Cleanup(func() {
		defer secure.Clear(cliValue)
		_ = c.clearIfUnchanged(cliValue)
	})
	for _, changed := range []bool{false, true} {
		cmd := exec.Command(binary, "clip", storePath, "TOKEN", "2")
		cmd.Env = append(os.Environ(), "SECRETS_DIR="+dir, "SECRETS_ENV="+filepath.Join(dir, "fallback.store"))
		started := time.Now()
		output, err := cmd.CombinedOutput()
		if err != nil || !bytes.Equal(output, []byte("copied TOKEN; clears in 2s if unchanged\n")) {
			t.Fatal("native clip status/message mismatch")
		}
		if time.Since(started) >= 2*time.Second {
			t.Fatal("clip waited for its clearer or inherited output handles")
		}
		if changed {
			if c.copy(replacement) != nil {
				t.Fatal("native clipboard replacement failed")
			}
			time.Sleep(3 * time.Second)
			assertNativeClipboard(t, c, replacement)
		} else {
			deadline := time.Now().Add(5 * time.Second)
			for {
				empty := false
				err := c.withOpen(func() error {
					var err error
					empty, err = nativeClipboardEmpty()
					return err
				})
				if err != nil {
					t.Fatal("native clipboard observation failed")
				}
				if empty {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("detached native clearer did not clear unchanged contents")
				}
				time.Sleep(20 * time.Millisecond)
			}
		}
	}
}

func assertNativeClipboard(t *testing.T, c windowsClipboard, value []byte) {
	t.Helper()
	if err := c.withOpen(func() error {
		want, _ := clipboardUTF16(value)
		defer secure.Clear(want)
		got, err := c.api.data(clipboardUnicodeText, len(want))
		defer secure.Clear(got)
		if err != nil || !bytes.Equal(got, want) {
			return errClipboard
		}
		return nil
	}); err != nil {
		t.Fatal("native clipboard replacement was changed")
	}
}
