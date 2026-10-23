package policy

import (
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
)

func TestArithmeticIntegerChildState(t *testing.T) {
	home, work, check := audit21Fixture(t)
	a := &analyzer{home: home, cwd: work, protected: check, deadline: time.Now().Add(time.Second)}
	a.noteIntegerVariable("n")
	a.arithmeticReference("ref", "n")
	a.arithmeticOpaque = true
	child := a.literalChild(work)
	if !child.possibleInteger("ref") || !child.arithmeticOpaque {
		t.Error("literal child lost arithmetic writer state")
	}
	child.arithmeticReference("ref", "other")
	if len(a.arithmeticRefs["ref"]) != 1 {
		t.Error("literal child changed parent reference alternatives")
	}
	child.noteIntegerVariable("other")
	child.fragment(`n=$operand`, 0)
	if child.reason != roles.Indeterminate {
		t.Errorf("integer assignment lost arithmetic context: %q", child.reason)
	}
	if a.integerVariables["other"] || a.reason != "" {
		t.Error("literal child changed parent integer state")
	}
}
