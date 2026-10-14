package roles

import "testing"

func TestPrinterTable(t *testing.T) {
	cases := []struct {
		name   string
		args   []string
		direct bool
		reason string
	}{
		{"gh", []string{"auth", "token"}, false, Printer},
		{"gh", []string{"auth", "token"}, true, ""},
		{"gh", []string{"auth", "status"}, false, ""},
		{"aws", []string{"--profile=work", "configure", "get", "AWS_SECRET_ACCESS_KEY"}, false, Printer},
		{"aws", []string{"configure", "get", "region"}, false, ""},
		{"op", []string{"item", "get", "mail", "--fields=password"}, false, Printer},
		{"pass", []string{"show", "mail"}, false, Printer},
		{"pass", []string{"ls"}, false, ""},
		{"secret-tool", []string{"search", "service", "mail"}, true, "secret-tool search prints secrets and is always denied"},
		{"security", []string{"find-generic-password", "-g"}, true, "security -g prints passwords to stderr and is always denied"},
		{"export", nil, false, Printer},
		{"ps", []string{"auxeww"}, false, Printer},
		{"echo", []string{"$API_TOKEN"}, false, Printer},
	}
	for _, c := range cases {
		t.Run(c.name+"/"+c.reason, func(t *testing.T) {
			if got := PrinterReason(c.name, c.args, c.direct); got != c.reason {
				t.Fatalf("got %q, want %q", got, c.reason)
			}
		})
	}
}
func TestOperandTable(t *testing.T) {
	protected := func(s string) bool { return s == ".env" }
	cases := []struct {
		name   string
		args   []string
		reason string
	}{
		{"cat", []string{".env"}, Reader},
		{"[", []string{"-f", ".env", "]"}, ""},
		{"ls", []string{".env"}, ""},
		{"git", []string{"check-ignore", ".env"}, ""},
		{"git", []string{"-c", "core.excludesfile=.env", "status"}, ""},
		{"grep", []string{"TOKEN", ".env"}, Reader},
		{"rg", []string{"-f", ".env"}, "pattern file targets a protected store"},
		{"dd", []string{"if=.env"}, FileInput},
		{"cp", []string{".env", "out"}, FileInput},
		{"cp", []string{"src", ".env"}, ""},
		{"openssl", []string{"-in", ".env"}, FileInput},
	}
	for _, c := range cases {
		t.Run(c.name+"/"+c.reason, func(t *testing.T) {
			if got := OperandReason(c.name, c.args, protected); got != c.reason {
				t.Fatalf("got %q want %q", got, c.reason)
			}
		})
	}
}
