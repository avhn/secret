package search

import "testing"

func TestM21MixedBraceSelectors(t *testing.T) {
	for _, tc := range []struct {
		glob                        string
		negative, narrow, protected bool
	}{
		{"{!*.md,*.secret}", false, false, true},
		{"{*.secret,!*.md}", false, false, true},
		{"*.secret", false, false, true},
		{"!*.md", true, false, false},
		{"*.md", false, true, false},
	} {
		t.Run(tc.glob, func(t *testing.T) {
			if got := NegativeGlob(tc.glob); got != tc.negative {
				t.Errorf("negative=%v want %v", got, tc.negative)
			}
			if got := CanNarrow(tc.glob); got != tc.narrow {
				t.Errorf("narrow=%v want %v", got, tc.narrow)
			}
			if got := Selector(tc.glob); got != tc.protected {
				t.Errorf("protected=%v want %v", got, tc.protected)
			}
		})
	}
}
