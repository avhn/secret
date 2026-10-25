package transport

import (
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// NewWindowsMatcher includes raw UTF-8 and both UTF-16 byte orders, without a BOM.
// Pattern bytes grow by at most 5x (ASCII is the worst case), but the existing
// 4 MiB aggregate matcher ceiling is unchanged and checked before allocation.
// Values stay borrowed bytes; derived encodings are cleared after construction,
// including on failure. This is not coverage for arbitrary code pages/transforms.
func NewWindowsMatcher(values [][]byte) (*Matcher, error) {
	var patterns, owned [][]byte
	defer func() {
		for _, value := range owned {
			clear(value)
		}
	}()
	total := 0
	for _, value := range values {
		if !utf8.Valid(value) {
			// Unselected loaded bytes may be non-UTF-8. Keep their raw pattern;
			// selected values are independently rejected at environment export.
			if len(value) > maxPatterns-total {
				return nil, errors.New("redaction pattern limit exceeded")
			}
			total += len(value)
			patterns = append(patterns, value)
			continue
		}
		units := 0
		for rest := value; len(rest) != 0; {
			r, n := utf8.DecodeRune(rest)
			units++
			if r > 0xffff {
				units++
			}
			rest = rest[n:]
		}
		if len(value) > maxPatterns-total || units > (maxPatterns-total-len(value))/4 {
			return nil, errors.New("redaction pattern limit exceeded")
		}
		total += len(value) + units*4
		le, be := make([]byte, 0, units*2), make([]byte, 0, units*2)
		appendUnit := func(unit uint16) {
			le = append(le, byte(unit), byte(unit>>8))
			be = append(be, byte(unit>>8), byte(unit))
		}
		for rest := value; len(rest) != 0; {
			r, n := utf8.DecodeRune(rest)
			if r <= 0xffff {
				appendUnit(uint16(r))
			} else {
				hi, lo := utf16.EncodeRune(r)
				appendUnit(uint16(hi))
				appendUnit(uint16(lo))
			}
			rest = rest[n:]
		}
		owned = append(owned, le, be)
		patterns = append(patterns, value, le, be)
	}
	return NewMatcher(patterns)
}
