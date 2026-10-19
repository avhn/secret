package store

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var assignment = regexp.MustCompile(`^[ \t\r\n\v\f]*(?:export[ \t\r\n\v\f]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
var header = regexp.MustCompile(`^\[((?:[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_][A-Za-z0-9_.-]*(?:,[A-Za-z_][A-Za-z0-9_]*=[A-Za-z0-9_][A-Za-z0-9_.-]*)*)?)\]$`)

// Record retains byte values, labels and source line, including repeated identities.
// Parse gives the caller independently owned Value bytes and Labels maps. The
// caller must clear Value when finished; selection helpers borrow these bytes.
type Record struct {
	Key          string
	Value        []byte
	Labels       map[string]string
	Line         int
	LabeledStore bool // A nonempty valid header occurs anywhere in this file.
}

type Warning struct {
	Line int
	Key  string
	Text string
}

// Parse reads LF-delimited bytes like the Bash CLI's Perl reader. Warnings
// contain names and line numbers only, never source values.
func Parse(data []byte) ([]Record, []Warning) {
	return parse(data, true)
}

// parse validates the same byte grammar in both modes. Metadata mode borrows
// source bytes for validation only and never allocates or retains a value copy.
func parse(data []byte, retainValues bool) ([]Record, []Warning) {
	var records []Record
	var warnings []Warning
	var ignored []string
	lines := make(map[string]int)
	labels := make(map[string]string)
	hasLabeledHeader := false
	for start, n := 0, 1; start < len(data); n++ {
		end := bytes.IndexByte(data[start:], '\n')
		var line []byte
		if end < 0 {
			line = data[start:]
			start = len(data)
		} else {
			line = data[start : start+end]
			start += end + 1
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
		}
		trimmed := bytes.TrimLeft(line, " \t\r\n\v\f")
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		if match := header.FindSubmatch(line); match != nil {
			next := make(map[string]string)
			valid := true
			if len(match[1]) > 0 {
				for _, pair := range strings.Split(string(match[1]), ",") {
					name, value, _ := strings.Cut(pair, "=")
					if _, exists := next[name]; exists {
						valid = false
						break
					}
					next[name] = value
				}
			}
			if valid {
				labels = next
				if len(next) > 0 {
					hasLabeledHeader = true
				}
				continue
			}
		}
		match := assignment.FindSubmatch(line)
		if match != nil && !bytes.ContainsAny(line, "\x00\r") {
			value := match[2]
			if len(value) > 0 && (value[0] == '\'' || value[0] == '"') {
				if len(value) > 1 && value[len(value)-1] == value[0] {
					value = value[1 : len(value)-1]
				} else {
					warnings = append(warnings, Warning{Line: n, Text: fmt.Sprintf("secret: malformed assignment ignored (line: %d)\n", n)})
					ignored = append(ignored, fmt.Sprint(n))
					continue
				}
			}
			key := string(match[1])
			signature := CanonicalLabels(labels)
			identity := key + "\x00" + signature
			if prior, exists := lines[identity]; exists {
				warnings = append(warnings, Warning{Line: n, Key: key, Text: fmt.Sprintf("secret: duplicate %s (lines: %d,%d); last wins\n", key, prior, n)})
			}
			lines[identity] = n
			copyLabels := make(map[string]string, len(labels))
			for k, v := range labels {
				copyLabels[k] = v
			}
			record := Record{Key: key, Labels: copyLabels, Line: n}
			if retainValues {
				record.Value = append([]byte(nil), value...)
			}
			records = append(records, record)
			continue
		}
		if bytes.IndexByte(line, '=') >= 0 {
			warnings = append(warnings, Warning{Line: n, Text: fmt.Sprintf("secret: malformed assignment ignored (line: %d)\n", n)})
		}
		ignored = append(ignored, fmt.Sprint(n))
	}
	if len(ignored) > 0 {
		warnings = append(warnings, Warning{Text: fmt.Sprintf("%d non-assignment lines ignored (lines: %s)\n", len(ignored), strings.Join(ignored, ","))})
	}
	for i := range records {
		records[i].LabeledStore = hasLabeledHeader
	}
	return records, warnings
}

func CanonicalLabels(labels map[string]string) string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	sort.Strings(names)
	pairs := make([]string, 0, len(names))
	for _, name := range names {
		pairs = append(pairs, name+"="+labels[name])
	}
	return strings.Join(pairs, ",")
}
