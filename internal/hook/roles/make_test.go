package roles

import (
	"reflect"
	"testing"
)

func TestNormalizeMakeArgs(t *testing.T) {
	for _, tc := range []struct {
		args, want []string
	}{
		{[]string{"-sE", "public:; echo ok", "-nEpublic:; echo ok"}, []string{"-s", "-E", "public:; echo ok", "-n", "-E", "public:; echo ok"}},
		{[]string{"-sCpublic", "-nfREADME.md", "-j4"}, []string{"-s", "-C", "public", "-n", "-f", "README.md", "-j", "4"}},
		{[]string{"-sE", "-sp", "--eval", "-np", "--", "-sE"}, []string{"-s", "-E", "-sp", "--eval", "-np", "--", "-sE"}},
		{[]string{"-sE"}, []string{"-s", "-E"}},
	} {
		if got := NormalizeMakeArgs(tc.args); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %q want %q", tc.args, got, tc.want)
		}
	}
	for _, args := range [][]string{{"-sE", "-sp"}, {"--eval", "-np"}, {"--e", "-np"}, {"-sCpublic", "-fpublic.mk"}} {
		if reason := PrinterReason("make", args, false); reason != "" {
			t.Errorf("option data became a printer flag: %q: %s", args, reason)
		}
	}
	if reason := PrinterReason("make", []string{"-sE", "public:; echo ok", "-np"}, false); reason == "" {
		t.Fatal("later database printer was hidden by an eval operand")
	}
}
