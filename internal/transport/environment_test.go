package transport

import (
	"reflect"
	"testing"
	"unicode/utf16"
)

func TestWindowsEnvironment(t *testing.T) {
	for _, test := range []struct {
		name string
		env  []string
		want []string
	}{
		{"empty", nil, nil},
		{"sort and round trip", []string{"z=last", "a=synthetic-\U00010437-\u00e9", "=C:=C:\\synthetic", "Empty=", "EQUAL=a=b"}, []string{"=C:=C:\\synthetic", "a=synthetic-\U00010437-\u00e9", "Empty=", "EQUAL=a=b", "z=last"}},
		{"unicode name", []string{"\u00e9=synthetic"}, []string{"\u00e9=synthetic"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			block, err := WindowsEnvironment(test.env)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(block)
			if len(block) < 2 || block[len(block)-1] != 0 || block[len(block)-2] != 0 {
				t.Fatal("environment lacks double NUL terminator")
			}
			var got []string
			start := 0
			for i, c := range block {
				if c == 0 && i > start {
					got = append(got, string(utf16.Decode(block[start:i])))
				}
				if c == 0 {
					start = i + 1
				}
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatal("environment did not round trip in sorted order")
			}
		})
	}
}

func TestWindowsEnvironmentRejectsLossAndAmbiguity(t *testing.T) {
	for _, env := range [][]string{
		{"A=synthetic\x00value"}, {"A\x00B=synthetic"}, {"A=\xff"}, {"\xff=synthetic"},
		{"A=one", "a=two"}, {"\u00e9=one", "\u00c9=two"}, {"=C:=one", "=c:=two"},
		{"=BAD=synthetic"}, {"=C:bad=synthetic"}, {"=1:=synthetic"}, {"=synthetic"}, {"MISSING"}, {""},
	} {
		block, err := WindowsEnvironment(env)
		if err != ErrWindowsEnvironment || block != nil {
			t.Fatal("unsafe environment accepted or diagnostic was not fixed")
		}
	}
}
