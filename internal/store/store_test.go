package store

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAndSelect(t *testing.T) {
	tests := []struct {
		name, source, selectors, wantBody, wantWarnings, wantError string
	}{
		{"flat last wins", "# ignored\nexport KEY='first $ # = \\ space'\nKEY=final\n", "", "  KEY=<5 bytes>\n", "secret: duplicate KEY (lines: 2,3); last wins\n", ""},
		{"labels and resets", "[zone=b,env=prod]\nKEY='one'\n[env=prod]\nKEY=second\n[]\nKEY=default\n", "env=prod zone=b", "  KEY [env=prod,zone=b]=<3 bytes>\n", "", ""},
		{"legacy brackets", "[env=prod]\nKEY=first\n[env=prod,env=qa]\nKEY=next\n", "env=prod", "  KEY [env=prod]=<4 bytes>\n", "secret: malformed assignment ignored (line: 3)\nsecret: duplicate KEY (lines: 2,4); last wins\n1 non-assignment lines ignored (lines: 3)\n", ""},
		{"malformed and ignored", "BAD='open\nNOT KEY=x\nBAD=x\x00y\nBAD=x\ry\n", "", "", "secret: malformed assignment ignored (line: 1)\nsecret: malformed assignment ignored (line: 2)\nsecret: malformed assignment ignored (line: 3)\nsecret: malformed assignment ignored (line: 4)\n4 non-assignment lines ignored (lines: 1,2,3,4)\n", ""},
		{"no trailing newline and crlf", "KEY=\xff$ # = \\ value\r\nOTHER=last", "", "  KEY=<14 bytes>\n  OTHER=<4 bytes>\n", "", ""},
		{"unmatched", "[env=prod]\nKEY=one\n", "env=qa", "  KEY=<unset>\n", "", ""},
		{"ambiguous", "[env=prod]\nKEY=one\n[zone=a]\nKEY=two\n", "env=prod zone=a", "", "", "ambiguous labels for KEY"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, warnings := Parse([]byte(tt.source))
			var diagnostic strings.Builder
			for _, warning := range warnings {
				diagnostic.WriteString(warning.Text)
			}
			if diagnostic.String() != tt.wantWarnings {
				t.Errorf("warnings = %q, want %q", diagnostic.String(), tt.wantWarnings)
			}
			selectors := make(Selectors)
			for _, pair := range strings.Fields(tt.selectors) {
				if err := selectors.AddSelector("--label", pair); err != nil {
					t.Fatal(err)
				}
			}
			selected, err := Select(records, selectors)
			if tt.wantError != "" {
				if err == nil || err.Error() != tt.wantError {
					t.Fatalf("selection error = %v, want %s", err, tt.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(ShowLines(records, true, selected), ""); got != tt.wantBody {
				t.Errorf("selected display = %q, want %q", got, tt.wantBody)
			}
			if tt.name == "flat last wins" && strings.Join(ShowLines(records, false, selected), "") != tt.wantBody {
				t.Error("flat display did not use last assignment")
			}
		})
	}
}

func TestHeaderWithoutLabeledAssignmentsPreservesDuplicates(t *testing.T) {
	records, _ := Parse([]byte("KEY=first\nKEY=last\n[env=prod]\n[]\n"))
	selected, err := Select(records, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "  KEY=<5 bytes>\n  KEY=<4 bytes>\n"
	if got := strings.Join(ShowLines(records, false, selected), ""); got != want {
		t.Errorf("unselected display = %q, want %q", got, want)
	}
}

func TestSelectors(t *testing.T) {
	tests := []struct{ option, pair, want string }{
		{"--env", "prod", ""}, {"--label", "env=prod", ""},
		{"--env", "qa", "conflicting label selector for env"},
		{"--label", "bad value=x", "invalid label selector"},
		{"--label", "env=bad value", "invalid label selector"},
	}
	selectors := make(Selectors)
	for _, tt := range tests {
		err := selectors.AddSelector(tt.option, tt.pair)
		if tt.want == "" && err != nil {
			t.Errorf("%s: %v", tt.pair, err)
		}
		if tt.want != "" && (err == nil || err.Error() != tt.want) {
			t.Errorf("%s: got %v, want %s", tt.pair, err, tt.want)
		}
	}
}

func TestResolve(t *testing.T) {
	home := filepath.Join("home", "test")
	dir := filepath.Join(home, ".secrets")
	path := func(name string) string { return filepath.Join(dir, name) }
	regular := map[string]bool{"local": true, path(".hidden.secret"): true, path("visible.secret"): true, filepath.Join(home, ".secrets.env"): true, path("z.secret"): true, path("spare.secret.bak"): true}
	loc := Locator{Home: home, IsFile: func(name string) bool { return regular[name] }, Glob: func(pattern string) ([]string, error) {
		switch pattern {
		case path("*.secret"):
			return []string{path("z.secret"), path("spare.secret.bak"), path("visible.secret")}, nil
		case path(".*.secret"):
			return []string{path(".hidden.secret")}, nil
		}
		return nil, nil
	}}
	for _, tt := range []struct{ name, want string }{
		{"local", "local"}, {"visible", path("visible.secret")}, {"hidden", path(".hidden.secret")},
		{"missing", path("missing.secret")}, {"file:local", "file:local"}, {"file:dir/file", "file:dir/file"},
		{"libsecret:good.1", "libsecret:good.1"}, {"keychain:_valid-1", "keychain:_valid-1"},
	} {
		got, err := loc.Resolve(tt.name)
		if err != nil || got != tt.want {
			t.Errorf("resolve %s: %q, %v", tt.name, got, err)
		}
	}
	for _, name := range []string{"keychain:bad/name", "keychain:", "libsecret:-bad", "libsecret:bad value"} {
		if _, err := loc.Resolve(name); err != ErrInvalidKeystoreName {
			t.Errorf("invalid reference %q: %v", name, err)
		}
	}
	got, err := loc.Defaults()
	want := []string{filepath.Join(home, ".secrets.env"), path("visible.secret"), path("z.secret"), path(".hidden.secret")}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("defaults = %v, %v; want %v", got, err, want)
	}
	loc.SecretsDir = filepath.Join("custom", "dir")
	loc.SecretsEnv = filepath.Join("custom", "entry.store")
	if got, err := loc.Resolve("missing"); err != nil || got != filepath.Join(loc.SecretsDir, "missing.secret") {
		t.Errorf("override resolution = %q, %v", got, err)
	}
}

func TestMerge(t *testing.T) {
	first, _ := Parse([]byte("KEY=first\nONLY=first\n"))
	second, _ := Parse([]byte("[env=qa]\nKEY=other\nOTHER=unused\n[]\nONLY=last\n"))
	a, _ := Select(first, Selectors{"env": "prod"})
	b, _ := Select(second, Selectors{"env": "prod"})
	merged := Merge(a, b)
	if !bytes.Equal(merged.Matched["KEY"].Value, []byte("first")) || !bytes.Equal(merged.Matched["ONLY"].Value, []byte("last")) {
		t.Error("unmatched overlay erased prior match, or matched overlay did not replace")
	}
	if _, ok := merged.Matched["OTHER"]; ok {
		t.Error("unmatched key exported")
	}
	if !reflect.DeepEqual(merged.Keys, []string{"KEY", "ONLY", "OTHER"}) || len(merged.AllValues) != 5 {
		t.Error("missing ambient keys or redaction values")
	}
}

// FuzzStoreParse uses synthetic sentinel values, never a real credential.
func FuzzStoreParse(f *testing.F) {
	for _, seed := range []string{"", "KEY=sentinelvalue012345\n", "[env=prod]\nKEY=sentinelvalue012345\r\n", "BAD='sentinelvalue012345\n", "KEY=\xffsentinelvalue012345"} {
		f.Add([]byte(seed))
	}
	fixtures := filepath.Join("..", "..", "testdata", "store", "fixtures")
	entries, err := os.ReadDir(fixtures)
	if err != nil {
		f.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".store" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(fixtures, entry.Name()))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, warningsA := Parse(data)
		b, warningsB := Parse(data)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(warningsA, warningsB) {
			t.Fatal("nondeterministic parse")
		}
		// Inject a value absent from the fuzz input, so its appearance in a
		// warning cannot be mistaken for a legitimately reported key name.
		const sentinel = "zz_fuzz_value_sentinel_012345"
		if !bytes.Contains(data, []byte(sentinel)) {
			probe := append(append([]byte(nil), data...), []byte("\nFUZZ_PROBE="+sentinel+"\nFUZZ_PROBE=other\n")...)
			_, warnings := Parse(probe)
			for _, warning := range warnings {
				if strings.Contains(warning.Text, sentinel) {
					t.Fatal("warning exposed synthetic value bytes")
				}
			}
		}
	})
}
