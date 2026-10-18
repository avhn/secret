package policy

import (
	"testing"
)

func TestAudit27ArithmeticTargets(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`echo $((++1))`, true},
		{`echo $((--1))`, true},
		{`echo $((1++))`, true},
		{`echo $((1--))`, true},
		{`echo $((++(1+2)))`, true},
		{`echo $((++x))`, false},
		{`echo $((x--))`, false},
		{`echo $((++a[0]))`, false},
		{`echo $((a[0]++))`, false},
		{`echo $(( ${x:-0} + 1 ))`, false},
		{`echo $(( $(printf 1) + 2 ))`, false},
		{`echo $((1 + $((2+3))))`, false},
		{`echo $(( $(cat .env) + 2 ))`, true},
	} {
		for _, source := range []string{tc.source, "bash -c " + shellLiteral(tc.source)} {
			if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
			}
		}
	}
}

func TestAudit27NestedIFSProof(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`IFS=''; s='hello world'; echo $s`, false},
		{`IFS=' '; echo $HOME`, false},
		{`IFS=$UNKNOWN; echo $HOME`, true},
		{`IFS=''; read IFS; echo $HOME`, true},
		{`IFS=''; IFS=$UNKNOWN; echo $HOME`, true},
		{`IFS=''; declare -n target=IFS; target=' '; echo $HOME`, true},
	} {
		for _, prefix := range []string{"", "env "} {
			source := prefix + "bash -c " + shellLiteral(tc.source)
			if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
			}
		}
	}
}

func TestAudit27ChildIFSDoesNotEscape(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`bash -c 'IFS=""; true'; SEP='cat .env'; $SEP`,
		`env bash -c 'IFS=""; true'; SEP='cat .env'; $SEP`,
		`bash -c 'IFS=""; true'; cat$IFS.env`,
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("child IFS certified parent expansion: %s", source)
		}
	}
}
