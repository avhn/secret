package store

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const storeTestdata = "../../testdata/store"

type goldenCase struct {
	name, mode           string
	options, files, keys []string
}

func readCases(t *testing.T, catalog string) []goldenCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(storeTestdata, catalog))
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenCase
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 5 {
			t.Fatalf("invalid case catalog row")
		}
		cases = append(cases, goldenCase{parts[0], parts[1], strings.Fields(parts[2]), strings.Fields(parts[3]), strings.Fields(parts[4])})
	}
	return cases
}

func emulateStoreCase(t *testing.T, tc goldenCase) (stdout, stderr []byte, status int) {
	t.Helper()
	selectors := make(Selectors)
	for i := 0; i < len(tc.options); i += 2 {
		if i+1 == len(tc.options) {
			return nil, []byte("secret: option needs an argument\n"), 1
		}
		if err := selectors.AddSelector(tc.options[i], tc.options[i+1]); err != nil {
			return nil, []byte("secret: " + err.Error() + "\n"), 1
		}
	}
	var selections []Selection
	for _, file := range tc.files {
		data, err := os.ReadFile(filepath.Join(storeTestdata, "fixtures", file))
		if err != nil {
			t.Fatal(err)
		}
		records, warnings := Parse(data)
		for _, warning := range warnings {
			stderr = append(stderr, warning.Text...)
		}
		selection, err := Select(records, selectors)
		if err != nil {
			return nil, append(stderr, []byte("secret: "+err.Error()+"\nsecret: store parsing failed\n")...), 1
		}
		selections = append(selections, selection)
		if tc.mode == "show" {
			stdout = append(stdout, file...)
			stdout = append(stdout, '\n')
			for _, line := range ShowLines(records, len(selectors) > 0, selection) {
				stdout = append(stdout, line...)
			}
		}
	}
	if tc.mode == "run" {
		merged := Merge(selections...)
		ambient := map[string][]byte{"KEY": []byte("ambient"), "TOKEN": []byte("ambient"), "SECOND": []byte("ambient"), "ONLY": []byte("ambient"), "OTHER": []byte("ambient")}
		for _, key := range merged.Keys {
			delete(ambient, key)
		}
		for key, record := range merged.Matched {
			ambient[key] = record.Value
		}
		for _, key := range tc.keys {
			if value, ok := ambient[key]; ok {
				stdout = fmt.Appendf(stdout, "%s=%d\n", key, len(value))
			} else {
				stdout = fmt.Appendf(stdout, "%s=<unset>\n", key)
			}
		}
	}
	return stdout, stderr, 0
}

func assertGoldens(t *testing.T, catalog string) {
	t.Helper()
	for _, tc := range readCases(t, catalog) {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, status := emulateStoreCase(t, tc)
			base := filepath.Join(storeTestdata, "golden", tc.name)
			for _, stream := range []struct {
				name string
				got  []byte
			}{{"stdout", stdout}, {"stderr", stderr}} {
				want, err := os.ReadFile(base + "." + stream.name)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(stream.got, want) {
					t.Errorf("%s bytes differ from Bash golden (got %d bytes, want %d)", stream.name, len(stream.got), len(want))
				}
			}
			want, err := os.ReadFile(base + ".status")
			if err != nil {
				t.Fatal(err)
			}
			wantStatus, err := strconv.Atoi(strings.TrimSpace(string(want)))
			if err != nil {
				t.Fatal(err)
			}
			if status != wantStatus {
				t.Errorf("exit status = %d, want %d", status, wantStatus)
			}
		})
	}
}

func TestStoreBashGoldens(t *testing.T) { assertGoldens(t, "cases.txt") }
