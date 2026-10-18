package policy

import (
	"strings"
	"testing"
)

func TestCurlFileURLWindowsHOME(t *testing.T) {
	_, work, _ := audit21Fixture(t)
	home := `C:\Users\RUNNER~1\AppData\Local\Temp\synthetic\home`
	for _, option := range []string{"", "--url ", "--url="} {
		for _, target := range []string{".aws/credentials", "README.md"} {
			source := "curl " + option + "file:$HOME/" + target + "?public"
			var names []string
			observed := false
			check := func(name, cwd string) bool {
				names = append(names, name)
				canonical := strings.ReplaceAll(name, `\`, "/")
				observed = observed || canonical == strings.ReplaceAll(home, `\`, "/")+"/"+target
				return canonical == strings.ReplaceAll(home, `\`, "/")+"/.aws/credentials"
			}
			if reason := Analyze(source, work, home, check); !observed || (reason != "") != (target == ".aws/credentials") {
				t.Errorf("%s: reason=%q observed=%v names=%q", source, reason, observed, names)
			}
		}
	}
}
