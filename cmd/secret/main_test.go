package main

import (
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	originalVersion := version
	t.Cleanup(func() { version = originalVersion })

	tests := []struct {
		name       string
		args       []string
		version    string
		wantStdout string
		wantStderr string
		wantStatus int
	}{
		{name: "default version", args: []string{"version"}, version: "dev", wantStdout: "secret dev (go)\n"},
		{name: "release version", args: []string{"version"}, version: "v1.2.3", wantStdout: "secret v1.2.3 (go)\n"},
		{name: "unsupported subcommand", args: []string{"list"}, wantStderr: "not yet implemented in the Go build; use bin/secret\n", wantStatus: 2},
		{name: "no subcommand", wantStderr: "not yet implemented in the Go build; use bin/secret\n", wantStatus: 2},
		{name: "extra version argument", args: []string{"version", "extra"}, wantStderr: "not yet implemented in the Go build; use bin/secret\n", wantStatus: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.version
			var stdout, stderr strings.Builder
			status := run(tt.args, &stdout, &stderr)
			if stdout.String() != tt.wantStdout || stderr.String() != tt.wantStderr || status != tt.wantStatus {
				t.Errorf("run(%q) = stdout %q, stderr %q, status %d; want stdout %q, stderr %q, status %d",
					tt.args, stdout.String(), stderr.String(), status, tt.wantStdout, tt.wantStderr, tt.wantStatus)
			}
		})
	}
}
