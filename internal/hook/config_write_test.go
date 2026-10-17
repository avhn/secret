package hook

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitConfigFileToolWrites(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	xdg := filepath.Join(root, "xdg")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", xdg)
	targets := []string{filepath.Join(root, ".git", "config"), filepath.Join(root, ".gitmodules"), filepath.Join(home, ".gitconfig"), filepath.Join(xdg, "git", "config")}
	for _, tool := range []string{"Write", "Edit", "MultiEdit", "NotebookEdit"} {
		for _, target := range targets {
			t.Run(tool+"/"+target, func(t *testing.T) {
				key := "file_path"
				if tool == "NotebookEdit" {
					key = "notebook_path"
				}
				payload, err := json.Marshal(map[string]any{"tool_name": tool, "cwd": root, "tool_input": map[string]string{key: target}})
				if err != nil {
					t.Fatal(err)
				}
				var out bytes.Buffer
				if err := Decide("claude", bytes.NewReader(payload), &out); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
					t.Fatalf("write target allowed: %s", out.String())
				}
			})
		}
	}
	for _, kind := range []string{"Add File", "Update File", "Delete File", "Move to"} {
		target := filepath.Join(xdg, "git", "config")
		header := "*** " + kind + ": " + target + "\n"
		if kind == "Move to" {
			header = "*** Update File: safe.txt\n" + header
		}
		patch := "*** Begin Patch\n" + header + "*** End Patch"
		payload, err := json.Marshal(map[string]any{"tool_name": "apply_patch", "cwd": root, "tool_input": map[string]string{"command": patch}})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if err := Decide("codex", bytes.NewReader(payload), &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
			t.Errorf("%s target allowed", kind)
		}
	}
	// The linked worktree's gitfile points outside a directory named .git.
	gitdir := filepath.Join(root, "worktree-gitdir")
	worktree := filepath.Join(root, "worktree")
	if err := os.MkdirAll(gitdir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitdir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"tool_name": "Write", "cwd": worktree, "tool_input": map[string]string{"file_path": filepath.Join(gitdir, "config")}})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Decide("claude", bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("worktree gitdir write allowed: %s", out.String())
	}
}

func TestOrdinaryWriteRemainsAllowed(t *testing.T) {
	root := t.TempDir()
	payload, err := json.Marshal(map[string]any{
		"tool_name": "Write", "cwd": root,
		"tool_input": map[string]string{"file_path": filepath.Join(root, "src", "new.ts"), "content": "synthetic"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Decide("claude", bytes.NewReader(payload), &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("ordinary write denied: %s", out.String())
	}
}
