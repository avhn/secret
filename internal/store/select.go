package store

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var ErrInvalidSelector = errors.New("invalid label selector")
var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var labelValue = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// Selectors is a validated set of CLI label selectors.
type Selectors map[string]string

// AddSelector maps --env to env= and accepts identical repeated pairs.
func (s Selectors) AddSelector(option, pair string) error {
	if option == "--env" {
		pair = "env=" + pair
	}
	name, value, ok := strings.Cut(pair, "=")
	if !ok || !keyName.MatchString(name) || !labelValue.MatchString(value) {
		return ErrInvalidSelector
	}
	if prior, exists := s[name]; exists && prior != value {
		return fmt.Errorf("conflicting label selector for %s", name)
	}
	s[name] = value
	return nil
}

// Selection keeps all parsed keys and values for ambient unsetting and
// redaction, including records not selected for export.
type Selection struct {
	Keys      []string
	Matched   map[string]Record
	AllValues [][]byte
}

// Select chooses the most-specific qualifying record for each key within
// one file; distinct equal-specificity winners are an error.
func Select(records []Record, selectors Selectors) (Selection, error) {
	result := Selection{Matched: make(map[string]Record)}
	seen := make(map[string]bool)
	ambiguous := make(map[string]bool)
	for _, record := range records {
		if !seen[record.Key] {
			seen[record.Key] = true
			result.Keys = append(result.Keys, record.Key)
		}
		result.AllValues = append(result.AllValues, record.Value)
		qualifies := true
		for name, value := range record.Labels {
			if selectors[name] != value {
				qualifies = false
				break
			}
		}
		if !qualifies {
			continue
		}
		prior, exists := result.Matched[record.Key]
		if !exists || len(prior.Labels) < len(record.Labels) {
			result.Matched[record.Key] = record
			delete(ambiguous, record.Key)
		} else if len(prior.Labels) == len(record.Labels) {
			if CanonicalLabels(prior.Labels) != CanonicalLabels(record.Labels) {
				ambiguous[record.Key] = true
			}
			result.Matched[record.Key] = record
		}
	}
	for _, key := range result.Keys {
		if ambiguous[key] {
			return Selection{}, fmt.Errorf("ambiguous labels for %s", key)
		}
	}
	return result, nil
}

// Merge overlays file selections in argument order. Unmatched later keys
// cannot erase matches from an earlier file.
func Merge(selections ...Selection) Selection {
	result := Selection{Matched: make(map[string]Record)}
	seen := make(map[string]bool)
	for _, selection := range selections {
		for _, key := range selection.Keys {
			if !seen[key] {
				seen[key] = true
				result.Keys = append(result.Keys, key)
			}
			if record, ok := selection.Matched[key]; ok {
				result.Matched[key] = record
			}
		}
		result.AllValues = append(result.AllValues, selection.AllValues...)
	}
	return result
}

// ShowLines matches the file-store body of Bash `show` (without its path).
// A flat store displays only the last assignment per key in first-key order.
func ShowLines(records []Record, selected bool, selection Selection) []string {
	var lines []string
	if selected {
		for _, key := range selection.Keys {
			if record, ok := selection.Matched[key]; ok {
				lines = append(lines, mask(record))
			} else {
				lines = append(lines, "  "+key+"=<unset>\n")
			}
		}
		return lines
	}
	labeled := false
	for _, record := range records {
		if record.LabeledStore {
			labeled = true
			break
		}
	}
	if labeled {
		for _, record := range records {
			lines = append(lines, mask(record))
		}
		return lines
	}
	last := make(map[string]Record)
	for _, record := range records {
		last[record.Key] = record
	}
	for _, key := range selection.Keys {
		lines = append(lines, mask(last[key]))
	}
	return lines
}

func mask(record Record) string {
	label := CanonicalLabels(record.Labels)
	if label != "" {
		return fmt.Sprintf("  %s [%s]=<%d bytes>\n", record.Key, label, len(record.Value))
	}
	return fmt.Sprintf("  %s=<%d bytes>\n", record.Key, len(record.Value))
}
