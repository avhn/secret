//go:build windows && windowsfixture

package main

import (
	"strings"
	"testing"
)

func TestSyntheticTarget(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "123")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	t.Setenv("GITHUB_JOB", "windows-cli")
	service := "secret/m5a-cli-123-2-windows-cli-" + strings.Repeat("a", 32)
	account := strings.Repeat("b", 32)
	for _, tc := range []struct {
		name, target string
		valid        bool
	}{
		{"exact", service + "/" + account, true},
		{"legacy lane", "secret/m5a-ci-" + strings.Repeat("a", 32) + "/" + account, false},
		{"real service", "secret/production/" + account, false},
		{"different run", "secret/m5a-cli-124-2-windows-cli-" + strings.Repeat("a", 32) + "/" + account, false},
		{"wildcard", service + "/*", false},
		{"adjacent", service + "-adjacent/" + account, false},
		{"uppercase account", service + "/" + strings.ToUpper(account), false},
		{"short account", service + "/a", false},
		{"short service", "secret/m5a-cli-a/" + account, false},
		{"extra segment", service + "/" + account + "/extra", false},
		{"NUL", service + "/" + account[:31] + "\x00", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if syntheticTarget(tc.target) != tc.valid {
				t.Fatal("exact synthetic target validation mismatch")
			}
		})
	}
}

func TestConsoleRejectsInvalidRequestsBeforeCreation(t *testing.T) {
	for _, req := range []request{
		{Executable: "relative.exe", Prompt: "TOKEN: ", Value: []byte("synthetic")},
		{Executable: `C:\synthetic\missing.exe`, Value: []byte("synthetic")},
		{Executable: `C:\synthetic\missing.exe`, Prompt: "TOKEN: "},
		{Mode: "get", Executable: `C:\synthetic\missing.exe`},
		{Executable: `C:\synthetic\missing.exe`, Prompt: "TOKEN: ", Value: []byte("bad\ninput")},
	} {
		if _, err := console(req); err == nil {
			t.Fatal("invalid console request accepted")
		}
	}
}

func TestJournalRequiresHostedProviderGate(t *testing.T) {
	t.Setenv("SECRET_REQUIRE_WINCRED", "")
	t.Setenv("RUNNER_TEMP", t.TempDir())
	if _, err := journalPath(); err == nil {
		t.Fatal("provider access accepted without explicit gate")
	}
	t.Setenv("SECRET_REQUIRE_WINCRED", "1")
	t.Setenv("RUNNER_TEMP", "relative")
	if _, err := journalPath(); err == nil {
		t.Fatal("relative journal root accepted")
	}
}
