package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestCurlFileURLPath(t *testing.T) {
	for _, tc := range []struct {
		url, path string
	}{
		{`file:C:\Users\synthetic\.aws\credentials`, `C:\Users\synthetic\.aws\credentials`},
		{`file:C:/Users/synthetic/.aws/credentials`, `C:/Users/synthetic/.aws/credentials`},
		{`FILE:C:/Users/synthetic/.aws/credentials`, `C:/Users/synthetic/.aws/credentials`},
		{`file:/C:/Users/synthetic/.aws/credentials`, `/C:/Users/synthetic/.aws/credentials`},
		{`file:///C:/Users/synthetic/.aws/credentials`, `/C:/Users/synthetic/.aws/credentials`},
		{`file://localhost/C:/Users/synthetic/.aws/credentials`, `/C:/Users/synthetic/.aws/credentials`},
		{`file:C:/Users/synthetic/public%20name`, `C:/Users/synthetic/public name`},
		{`file:/C:/Users/synthetic/public%23name`, `/C:/Users/synthetic/public#name`},
		{`file:/synthetic/.aws/credentials`, `/synthetic/.aws/credentials`},
	} {
		for _, suffix := range []string{"", "?public", "#public", "?public#fragment"} {
			t.Run(tc.url+suffix, func(t *testing.T) {
				want := tc.path
				if runtime.GOOS == "windows" && len(want) > 2 && want[0] == '/' && want[2] == ':' {
					want = want[1:]
				}
				want = filepath.FromSlash(want)
				name, local, valid := curlFileURLPath(tc.url + suffix)
				if !local || !valid || name != want {
					t.Fatalf("path = %q, local = %v, valid = %v; want %q, true, true", name, local, valid, want)
				}
			})
		}
	}
	for _, value := range []string{
		`file:C:/synthetic/public%09name?public`,
		`file:C:/synthetic/public%0Aname#public`,
		`file:C:/synthetic/public%0Dname`,
		`file:C:/synthetic/public%7Fname`,
		`file:C:/synthetic/public%00name`,
		`file:C:/synthetic/public%GGname`,
		`file://remote/synthetic/public`,
	} {
		if name, local, valid := curlFileURLPath(value); !local || valid {
			t.Errorf("%s: path = %q, local = %v, valid = %v; want local invalid URL", value, name, local, valid)
		}
	}
	if _, local, valid := curlFileURLPath("https://synthetic.invalid/.env?public"); local || !valid {
		t.Errorf("web URL: local = %v, valid = %v", local, valid)
	}
}

func TestCurlFileURLDriveInputs(t *testing.T) {
	// Quoted shell words bypass glob expansion, exercising curl's URL parsing
	// independently of the shell's unmatched-glob preservation policy.
	home, work, check := audit21Fixture(t)
	for _, value := range []string{
		`file:C:\Users\synthetic\.env?public`,
		`file:C:/Users/synthetic/.env?public`,
		`file:/C:/Users/synthetic/.env#public`,
		`file:///C:/Users/synthetic/.env?public#fragment`,
	} {
		for _, option := range []string{"", "--url ", "--url="} {
			if reason := Analyze("curl "+option+shellLiteral(value), work, home, check); reason == "" {
				t.Errorf("curl %s%s: allowed protected URL", option, value)
			}
		}
		if reason := AnalyzeArgv([]string{"curl", "--url", value}, work, home, check); reason == "" {
			t.Errorf("curl --url %s: argv allowed protected URL", value)
		}
	}
}
