//go:build windows

package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsGrepNamesOnlyCredentialRoles(t *testing.T) {
	home, work := windowsHookFixture(t)
	aws := filepath.Join(home, ".aws")
	if err := os.Mkdir(aws, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"credentials", "public.txt"} {
		if err := os.WriteFile(filepath.Join(aws, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(work, "profile")
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", profile, home).CombinedOutput(); err != nil {
		t.Fatalf("required ancestor junction fixture: %v (%s)", err, output)
	}
	alias := filepath.Join(work, "alias.txt")
	if err := os.Symlink(filepath.Join(aws, "credentials"), alias); err != nil {
		t.Fatalf("required credential symlink fixture: %v", err)
	}
	for _, root := range []string{aws, filepath.Join(profile, ".aws"), alias} {
		t.Run(root, func(t *testing.T) {
			for _, mode := range []string{"default", "files_with_matches"} {
				fields := map[string]any{"path": root, "pattern": "SYNTHETIC"}
				if mode != "default" {
					fields["output_mode"] = mode
				}
				windowsHookCheck(t, "Grep", work, fields, "")
			}
			for _, mode := range []string{"content", "count", ""} {
				audit28ToolCheck(t, "Grep", work, map[string]any{"path": root, "pattern": "SYNTHETIC", "output_mode": mode}, true)
			}
		})
	}
	for _, mode := range []string{"files_with_matches", "content", "count"} {
		audit28ToolCheck(t, "Grep", work, map[string]any{"path": filepath.Join(aws, "credentials"), "output_mode": mode}, true)
		windowsHookCheck(t, "Grep", work, map[string]any{"path": filepath.Join(aws, "public.txt"), "output_mode": mode}, "")
	}
	// Hiding the credential-directory role itself is still a denial, including
	// names mode. Ancestor aliases above do not hide the explicit .aws component.
	opaque := filepath.Join(work, "opaque")
	if output, err := exec.Command(filepath.Join(system, "cmd.exe"), "/d", "/c", "mklink", "/J", opaque, aws).CombinedOutput(); err != nil {
		t.Fatalf("required opaque junction fixture: %v (%s)", err, output)
	}
	windowsHookCheck(t, "Grep", work, map[string]any{"path": opaque, "output_mode": "files_with_matches"}, "file access targets a protected store")
	for _, tc := range []struct{ name, target string }{
		{"directory-link", aws},
		{"dangling-link", filepath.Join(aws, "missing")},
	} {
		name := filepath.Join(work, tc.name)
		if err := os.Symlink(tc.target, name); err != nil {
			t.Fatalf("required native symlink fixture: %v", err)
		}
		windowsHookCheck(t, "Grep", work, map[string]any{"path": name, "output_mode": "files_with_matches"}, "file access targets a protected store")
	}
}
