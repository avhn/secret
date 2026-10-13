package corpus

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestInventory checks that every committed shell case has a unique key and a
// valid expectation. Translated Go cases must refer to these suite/name keys.
func TestInventory(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "inventory", "*.tsv"))
	if err != nil || len(files) == 0 {
		t.Fatalf("find inventories: %v (files: %d)", err, len(files))
	}
	for _, suite := range []string{"guard", "secret", "backends", "codex", "libsecret"} {
		path := filepath.Join("..", "..", "testdata", "inventory", suite+".tsv")
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required inventory %s: %v", suite, err)
		}
	}
	validStatus := regexp.MustCompile(`^[0-9]+$`)
	seen := make(map[string]string)
	for _, path := range files {
		if filepath.Base(path) == "go-expected-divergence.tsv" {
			continue // Three-column expected failures are checked by tests/check-go-divergence.py.
		}
		// SUITE.darwin.tsv overrides carry the same suite name as SUITE.tsv.
		suite := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".tsv"), ".darwin")
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scan := bufio.NewScanner(f)
		line := 0
		for scan.Scan() {
			line++
			fields := strings.Split(scan.Text(), "\t")
			if len(fields) != 4 || fields[0] != suite || fields[1] == "" {
				t.Errorf("%s:%d: invalid suite, name or field count", path, line)
				continue
			}
			// Keys are unique within each file; an override repeats its base keys.
			key := path + "|" + fields[0] + "/" + fields[1]
			if first, exists := seen[key]; exists {
				t.Errorf("%s:%d: duplicate %s (first in %s)", path, line, key, first)
			}
			seen[key] = fmt.Sprintf("%s:%d", path, line)
			switch fields[2] {
			case "decision":
				if fields[3] != "allow" && fields[3] != "deny" {
					t.Errorf("%s:%d: invalid decision %q", path, line, fields[3])
				}
			case "check", "assert":
				if !validStatus.MatchString(fields[3]) || (fields[2] == "assert" && fields[3] != "0") {
					t.Errorf("%s:%d: invalid status %q", path, line, fields[3])
				}
			default:
				t.Errorf("%s:%d: invalid kind %q", path, line, fields[2])
			}
		}
		if err := scan.Err(); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if err := f.Close(); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}
