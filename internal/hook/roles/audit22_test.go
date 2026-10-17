package roles

import (
	"strings"
	"testing"
)

func TestAudit22BooleanPrinterOptions(t *testing.T) {
	for _, command := range []string{
		"gh auth status --show-token=", "op item get synthetic --reveal=", "kubectl config view --raw=",
		"op item get synthetic --otp=", "op signin --raw=", "az acr login --expose-token=",
	} {
		for _, value := range []string{"true", "TRUE", "True", "1", "yes", "YES", "on", "On", "false", "FALSE", "False", "0", "no", "NO", "off", "Off"} {
			words := strings.Fields(command + value)
			want := strings.Contains(" true 1 yes on ", " "+strings.ToLower(value)+" ")
			if got := PrinterReason(words[0], words[1:], false); (got != "") != want {
				t.Errorf("%s%s: reason=%q want printer=%v", command, value, got, want)
			}
		}
	}
}

func TestAudit22ContentFormatsAndOpActions(t *testing.T) {
	for _, format := range []string{
		"json", "yaml", "jsonpath={.data}", "jsonpath-as-json={.data}", "jsonpath-file=public.tpl",
		"go-template={{.data}}", "go-template-file=public.tpl", "template={{.data}}", "templatefile=public.tpl",
		"custom-columns=DATA:.data", "custom-columns-file=public.tpl", "name", "wide",
	} {
		for _, option := range []string{"-o " + format, "-o" + format, "--output " + format, "--output=" + format} {
			for _, resource := range []string{"secret", "secrets", "secret/synthetic", "pods,secrets"} {
				words := strings.Fields("kubectl --context synthetic get " + resource + " " + option)
				want := format != "name" && format != "wide"
				for _, direct := range []bool{false, true} {
					if got := PrinterReason(words[0], words[1:], direct); (got != "") != want {
						t.Errorf("%v direct=%v: reason=%q want printer=%v", words, direct, got, want)
					}
				}
			}
			words := strings.Fields("kubectl get pods " + option)
			if got := PrinterReason(words[0], words[1:], false); got != "" {
				t.Errorf("public resource %v: %s", words, got)
			}
		}
	}
	for _, tc := range []struct {
		command string
		deny    bool
	}{
		{"op item get synthetic --otp", true}, {"op signin --raw", true},
		{"op --account synthetic item get synthetic --otp", true},
		{"op --account=synthetic signin --raw", true},
		{"op item get synthetic", false}, {"op item list --otp", false},
		{"op signin", false}, {"op account list --raw", false},
	} {
		words := strings.Fields(tc.command)
		for _, direct := range []bool{false, true} {
			if got := PrinterReason(words[0], words[1:], direct); (got != "") != (tc.deny && !direct) {
				t.Errorf("%s direct=%v: reason=%q", tc.command, direct, got)
			}
		}
	}
}
