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

// TestOptionBoundaries covers real option arity, clusters, abbreviations and --.
func TestOptionBoundaries(t *testing.T) {
	protected := func(s string) bool { return s == ".env" || s == "-r.env" }
	for _, tc := range []struct {
		name string
		args []string
		deny bool
	}{
		{"grep", []string{"-rl", "x", "src"}, false},
		{"grep", []string{"-Rn", "x", "src"}, true},
		{"grep", []string{"-rievalue", "src"}, true},
		{"grep", []string{"-ier", "safe"}, false},
		{"grep", []string{"-e", "-r", "safe"}, false},
		{"grep", []string{"--", "-r", "safe"}, false},
		{"grep", []string{"--rec", "x", "src"}, true},
		{"grep", []string{"--dereference-r", "x", "src"}, true},
		{"grep", []string{"--dir=recurse", "x", "src"}, true},
		{"grep", []string{"-drecurse", "x", "src"}, true},
		{"grep", []string{"-if.env", "safe"}, true},
		{"grep", []string{"-ie", "x", ".env"}, true},
		{"grep", []string{"--fi=.env", "safe"}, true},
		{"grep", []string{"--exclude-f=.env", "x", "safe"}, true},
		{"grep", []string{"--", "x", "-r.env"}, true},
		{"split", []string{"--lines", "5", ".env"}, true},
		{"split", []string{"--lin=5", ".env"}, true},
		{"split", []string{"-dl5", ".env"}, true},
		{"split", []string{"-t", ":", ".env"}, true},
		{"split", []string{"--additional-suffix", "txt", ".env"}, true},
		{"split", []string{"--", ".env", "out"}, true},
		{"split", []string{"--filter=cat .env", "safe"}, true},
		{"split", []string{"--lines=5", "safe", ".env"}, false},
		{"split", []string{"--additional-suffix", ".env", "safe"}, false},
	} {
		if got := OperandReason(tc.name, tc.args, protected); (got != "") != tc.deny {
			t.Errorf("%s %q: reason %q, deny=%v", tc.name, tc.args, got, tc.deny)
		}
	}
}
