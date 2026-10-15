package policy

import "mvdan.cc/sh/v3/syntax"

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
	count := 1
	for _, part := range word.Parts {
		brace, ok := part.(*syntax.BraceExp)
		if !ok {
			continue
		}
		if brace.Sequence || len(brace.Elems) > 64 {
			return 0, false
		}
		alternatives := 0
		for _, elem := range brace.Elems {
			n, ok := braceWordCount(elem)
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
