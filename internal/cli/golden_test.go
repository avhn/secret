package cli_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/cli"
)

func TestBashGoldens(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Bash golden generation, TTY and clipboard tools require Unix hosts")
	}
	root := filepath.Join("..", "..")
	binary := filepath.Join(t.TempDir(), "secret")
	build := exec.Command("go", "build", "-o", binary, "./cmd/secret")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s: %v", output, err)
	}
	catalog, err := os.ReadFile(filepath.Join(root, "testdata", "cli", "cases.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join(root, "testdata", "store", "fixtures")
	count := 0
	for _, line := range strings.Split(string(catalog), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 3 {
			t.Fatalf("invalid case: %s", line)
		}
		name, args := fields[0], strings.Fields(fields[2])
		for i := range args {
			if args[i] == "@child" {
				path, e := filepath.Abs(filepath.Join(root, "testdata", "cli", "child.pl"))
				if e != nil {
					t.Fatal(e)
				}
				args[i] = path
			}
		}
		count++
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			home := filepath.Join(dir, "home")
			stores := filepath.Join(dir, "stores")
			work := filepath.Join(dir, "work")
			for _, p := range []string{home, stores, work} {
				if err := os.Mkdir(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			// Keep the same fixture basename and relative stdout path as the Bash generator.
			entries, err := os.ReadDir(fixtureDir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".store") {
					continue
				}
				data, er := os.ReadFile(filepath.Join(fixtureDir, entry.Name()))
				if er != nil {
					t.Fatal(er)
				}
				if er = os.WriteFile(filepath.Join(work, entry.Name()), data, 0600); er != nil {
					t.Fatal(er)
				}
			}
			cmd := exec.Command(binary, args...)
			cmd.Dir = work
			cmd.Env = append(os.Environ(), "HOME="+home, "SECRETS_DIR="+stores, "SECRETS_ENV="+filepath.Join(home, "fallback.store"), "LC_ALL=C")
			if name == "stash_valid" {
				cmd.Stdin = strings.NewReader("synthetic\n")
			}
			var out, errOut bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &errOut
			err = cmd.Run()
			status := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					status = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			goldenDir := filepath.Join(root, "testdata", "cli", "golden")
			for ext, got := range map[string][]byte{"stdout": out.Bytes(), "stderr": errOut.Bytes()} {
				want, er := os.ReadFile(filepath.Join(goldenDir, name+"."+ext))
				if er != nil {
					t.Fatal(er)
				}
				// M3 adds Go-only commands and corrects supervisor documentation.
				// Keep the Bash help fixture frozen for its own compatibility gate.
				if name == "help" && ext == "stdout" {
					want = []byte(cli.UsageForTest)
				}
				if !bytes.Equal(got, want) {
					t.Errorf("%s: got %q, want %q", ext, got, want)
				}
			}
			want, er := os.ReadFile(filepath.Join(goldenDir, name+".status"))
			if er != nil {
				t.Fatal(er)
			}
			expected, er := strconv.Atoi(strings.TrimSpace(string(want)))
			if er != nil {
				t.Fatal(er)
			}
			if status != expected {
				t.Errorf("status: got %d, want %d (Bash %s)", status, expected, strings.TrimSpace(string(want)))
			}
		})
	}
	t.Logf("compared %d synthetic CLI cases", count)
}

// A subprocess must perform the delayed clear after the original CLI exits.
func TestClipboardClearAfterExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("clipboard stub uses Unix shell scripts")
	}
	root := filepath.Join("..", "..")
	binary := filepath.Join(t.TempDir(), "secret")
	build := exec.Command("go", "build", "-o", binary, "./cmd/secret")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %s: %v", output, err)
	}
	dir := t.TempDir()
	tools := filepath.Join(dir, "tools")
	if err := os.Mkdir(tools, 0700); err != nil {
		t.Fatal(err)
	}
	clip := filepath.Join(dir, "clipboard")
	storeFile := filepath.Join(dir, "synthetic.store")
	if err := os.WriteFile(storeFile, []byte("TOKEN=synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{"pbcopy": "#!/bin/sh\ncat > \"$SYNTH_CLIP\"\n", "pbpaste": "#!/bin/sh\ncat \"$SYNTH_CLIP\"\n"} {
		if err := os.WriteFile(filepath.Join(tools, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(binary, "clip", storeFile, "TOKEN", "0")
	cmd.Env = append(os.Environ(), "HOME="+dir, "SECRETS_DIR="+dir, "SYNTH_CLIP="+clip, "PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clip: %s: %v", output, err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(clip)
		if err == nil && len(data) == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("clipboard was not cleared after the CLI exited")
}
