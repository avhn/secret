package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", filepath.Join(home, "stores"))
	t.Setenv("SECRETS_ENV", filepath.Join(home, "fallback.store"))
	originalVersion := version
	t.Cleanup(func() { version = originalVersion })
	tests := []struct {
		name                    string
		args                    []string
		version, stdout, stderr string
		status                  int
	}{
		{name: "default version", args: []string{"version"}, version: "dev", stdout: "secret dev (go)\n"},
		{name: "release version", args: []string{"version"}, version: "v1.2.3", stdout: "secret v1.2.3 (go)\n"},
		{name: "empty list", args: []string{"list"}, stderr: "no secret stores found\n"},
		{name: "no subcommand", stderr: "secret: subcommand required; use secret help\n", status: 1},
		{name: "extra version argument", args: []string{"version", "extra"}, stderr: "secret: version takes no arguments\n", status: 1},
		{name: "run pending", args: []string{"run"}, stderr: "secret: not yet implemented in the Go build; use bin/secret\n", status: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.version
			var stdout, stderr strings.Builder
			status := run(tt.args, &stdout, &stderr)
			if stdout.String() != tt.stdout || stderr.String() != tt.stderr || status != tt.status {
				t.Errorf("stdout %q, stderr %q, status %d; want %q, %q, %d", stdout.String(), stderr.String(), status, tt.stdout, tt.stderr, tt.status)
			}
		})
	}
}
