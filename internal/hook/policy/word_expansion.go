package policy

import (
	"strconv"

	"mvdan.cc/sh/v3/syntax"
)

// expandedOperand keeps role classification aligned with the actual argv fields,
// including brace-expanded option words and unresolved operand placeholders.
type expandedOperand struct {
	value  string
	source *syntax.Word
	known  bool
}

// braceWordCount bounds alternatives before the lazy AST-only expansion. Sequence
// expansion remains unsupported, matching the existing policy's grammar budget.
func braceWordCount(word *syntax.Word) (int, bool) {
	return boundedBraceCount(word, false)
}

// A bounded sequence remains unsupported for reader certification, but its
// size must still be checked before echo/printf can discard word uncertainty.
func boundedBraceCount(word *syntax.Word, sequences bool) (int, bool) {
	count := 1
	for _, part := range word.Parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		if brace.Sequence {
			if !sequences {
				return 0, false
			}
			n, ok := braceSequenceCount(brace)
			if !ok || count*n > 64 {
				return 0, false
			}
			count *= n
			continue
		}
		if len(brace.Elems) > 64 {
			return 0, false
		}
		alternatives := 0
		for _, elem := range brace.Elems {
			n, ok := boundedBraceCount(elem, sequences)
			if !ok || alternatives+n > 64 {
				return 0, false
			}
			alternatives += n
		}
		count *= alternatives
		if count > 64 {
			return 0, false
		}
	}
	return count, true
}

func braceSequenceCount(brace *syntax.BraceExp) (int, bool) {
	if len(brace.Elems) < 2 || len(brace.Elems) > 3 {
		return 0, false
	}
	values := []int64{0, 0, 1}
	for i, elem := range brace.Elems {
		text := elem.Lit()
		if len(text) == 0 || len(text) > 6 {
			return 0, false
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			if i >= 2 || len(text) != 1 || !(text[0] >= 'a' && text[0] <= 'z' || text[0] >= 'A' && text[0] <= 'Z') {
				return 0, false
			}
			n = int64(text[0])
		}
		values[i] = n
	}
	span, step := values[1]-values[0], values[2]
	if span < 0 {
		span = -span
	}
	if step < 0 {
		step = -step
	}
	if step == 0 {
		step = 1
	}
	n := span/step + 1
	return int(n), n <= 64
}
