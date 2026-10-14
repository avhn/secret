package policy

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func protected(name, cwd string) bool {
	return filepath.Base(filepath.Join(cwd, name)) == ".env" || strings.Contains(filepath.Join(cwd, name), "/.secrets/")
}

func TestASTPaths(t *testing.T) {
	cases := []struct{ src, reason string }{
		{"cat .env", "reader targets a protected store"},
		{"cat .env.example", ""},
		{"ls .env", ""},
		{"(cat .env)", "reader targets a protected store"},
		{"echo $(cat .env)", "reader targets a protected store"},
		{"cat <(cat .env)", "reader targets a protected store"},
		{"wc < .env", "input redirect reads a protected store"},
		{"function readit() { cat .env; }", "reader targets a protected store"},
		{"bash -c 'cat .env'", "reader targets a protected store"},
		{"eval 'cat .env'", "reader targets a protected store"},
		{"gh auth token", "credential printer requires a direct pipe to secret stash FILE KEY"},
		{"gh auth token | secret stash svc KEY", ""},
		{"gh auth token | cat | secret stash svc KEY", "credential printer requires a direct pipe to secret stash FILE KEY"},
		{"echo $API_TOKEN", "credential printer requires a direct pipe to secret stash FILE KEY"},
		{"cat {src,.env}", "reader targets a protected store"},
		{"cat .secrets/a", "reader targets a protected store"},
		{"cat .env >out", "reader targets a protected store"},
		{"ls .env | xargs cat", "xargs reader consumes a protected-name listing"},
		{"xargs -a.env cat", "xargs arg-file reads a protected store"},
		{"timeout 5 cat .env", "reader targets a protected store"},
		{"env -S 'cat .env'", "command too complex to analyse for secret access; split it or use secret run"},
		{"docker compose --env-file .env config", "compose config prints env-file values"},
		{"dotenv -e .env -- printenv", "credential printer requires a direct pipe to secret stash FILE KEY"},
		{"grep -R TOKEN src", "recursive grep bypasses protected search defaults; use plain rg"},
		{"rg TOKEN src", "search scope is uncertain; narrow the path or use -l; install examples/ripgreprc for rg"},
		{"git grep TOKEN", "search scope is uncertain; narrow the path or use -l; install examples/ripgreprc for rg"},
	}
	for _, c := range cases {
		t.Run(c.src, func(t *testing.T) {
			if got := Analyze(c.src, "/synthetic", "/synthetic", protected); got != c.reason {
				t.Fatalf("got %q want %q", got, c.reason)
			}
		})
	}
}

func TestReadingProtectedLiteral(t *testing.T) {
	for _, path := range []string{".env", ".secrets/item"} {
		for _, command := range []string{"cat", "head", "tail", "wc", "sort", "cp", "openssl -in"} {
			src := command + " " + path
			if command == "cp" {
				src += " output"
			}
			if got := Analyze(src, "/synthetic", "/synthetic", protected); got == "" {
				t.Fatalf("allowed protected input %q", src)
			}
		}
	}
}

func TestBudgets(t *testing.T) {
	if got := Analyze("cat .env "+strings.Repeat("x", 8192), "/synthetic", "/synthetic", protected); got != "command too complex to analyse for secret access; split it or use secret run" {
		t.Fatalf("source budget: %q", got)
	}
	if got := Analyze(strings.Repeat("echo x; ", 130)+"cat .env", "/synthetic", "/synthetic", protected); got == "" {
		t.Fatal("word budget allowed protected read")
	}
	if got := Analyze("cat {"+strings.Repeat("a,", 65)+".env}", "/synthetic", "/synthetic", protected); got == "" {
		t.Fatal("brace budget allowed protected read")
	}
}

func FuzzAnalyze(f *testing.F) {
	for _, seed := range []string{"cat .env", "cat {a,b}", "$(cat .env)", "echo 'x'", strings.Repeat("x", 8193), "bash -c 'bash -c \"cat .env\"'"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, src string) {
		if len(src) > 10000 {
			t.Skip()
		}
		start := time.Now()
		_ = Analyze(src, "/synthetic", "/synthetic", protected)
		if time.Since(start) > 5*time.Second {
			t.Fatal("analysis exceeded hook deadline")
		}
		if len(src) > 8192 && CheckBudget(src) != ErrIndeterminate {
			t.Fatal("missing source budget")
		}
	})
}
