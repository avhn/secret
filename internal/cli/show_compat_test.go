package cli

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/avhn/secret/internal/testutil"
)

// These exact text goldens protect the value-aware legacy show path when the
// names-only JSON reader is wired into dispatch. Lengths are bytes, not runes.
func TestShowLegacyTextGoldens(t *testing.T) {
	for _, tt := range []struct {
		name    string
		data    []byte
		options []string
		body    string
		stderr  string
	}{
		{
			name:   "flat duplicates retain first key order and last byte length",
			data:   []byte("TOKEN=synthetic-first\nOTHER=x\nTOKEN=é\n"),
			body:   "  TOKEN=<2 bytes>\n  OTHER=<1 bytes>\n",
			stderr: "secret: duplicate TOKEN (lines: 1,3); last wins\n",
		},
		{
			name:   "labeled duplicates remain ordered",
			data:   []byte("TOKEN=base\n[region=west,env=prod]\nTOKEN=one\nTOKEN=longer\n[]\nEMPTY=\n"),
			body:   "  TOKEN=<4 bytes>\n  TOKEN [env=prod,region=west]=<3 bytes>\n  TOKEN [env=prod,region=west]=<6 bytes>\n  EMPTY=<0 bytes>\n",
			stderr: "secret: duplicate TOKEN (lines: 3,4); last wins\n",
		},
		{
			name:    "selected masks and explicit unset",
			data:    []byte("TOKEN=base\n[env=prod]\nTOKEN=production\nONLY_PROD=only\n[env=dev]\nDEV=dev\n"),
			options: []string{"--env", "prod"},
			body:    "  TOKEN [env=prod]=<10 bytes>\n  ONLY_PROD [env=prod]=<4 bytes>\n  DEV=<unset>\n",
		},
		{
			name:    "selected falls back to unlabeled",
			data:    []byte("TOKEN=base\n[env=prod]\nTOKEN=production\nONLY_PROD=only\n"),
			options: []string{"--env", "qa"},
			body:    "  TOKEN=<4 bytes>\n  ONLY_PROD=<unset>\n",
		},
		{
			name: "crlf quoted raw and invalid utf8 byte lengths",
			data: []byte("QUOTED='é'\r\nRAW=$literal#=\\\r\nBINARY=\xff\xfe\r\n"),
			body: "  QUOTED=<2 bytes>\n  RAW=<11 bytes>\n  BINARY=<2 bytes>\n",
		},
		{
			name:   "malformed assignment warnings stay exact",
			data:   []byte("TOKEN='unterminated\nGOOD=synthetic\n"),
			body:   "  GOOD=<9 bytes>\n",
			stderr: "secret: malformed assignment ignored (line: 1)\n1 non-assignment lines ignored (lines: 1)\n",
		},
		{
			name: "empty store",
			data: []byte("# synthetic empty store\n"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := testutil.TempDir(t)
			t.Setenv("HOME", home)
			t.Setenv("SECRETS_DIR", filepath.Join(home, "stores"))
			t.Setenv("SECRETS_ENV", filepath.Join(home, "missing.env"))
			path := filepath.Join(home, "synthetic.secret")
			if err := testutil.WriteFile(path, tt.data, 0600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"show"}, tt.options...)
			args = append(args, "file:"+path)
			var out, errOut bytes.Buffer
			status := Main(args, nil, &out, &errOut)
			if status != 0 || out.String() != "file:"+path+"\n"+tt.body || errOut.String() != tt.stderr {
				t.Errorf("legacy show changed: status %d stdout %q stderr %q", status, out.String(), errOut.String())
			}
		})
	}
}

func TestShowLegacyProviderTextGolden(t *testing.T) {
	home := testutil.TempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("SECRETS_DIR", home)
	t.Setenv("SECRETS_ENV", filepath.Join(home, "missing.env"))
	manifest := []byte("secret-manifest-v1\nbackend=libsecret\nTOKEN\t\t0123456789abcdef0123456789abcdef\nTOKEN\tenv=prod\tfedcba9876543210fedcba9876543210\nPROD\tenv=prod\t11111111111111111111111111111111\n")
	if err := testutil.WriteFile(filepath.Join(home, "synthetic.keys"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		options []string
		body    string
	}{
		{nil, "  TOKEN=<stored>\n  TOKEN [env=prod]=<stored>\n  PROD [env=prod]=<stored>\n"},
		{[]string{"--env", "prod"}, "  TOKEN [env=prod]=<stored>\n  PROD [env=prod]=<stored>\n"},
		{[]string{"--env", "qa"}, "  TOKEN=<stored>\n  PROD=<unset>\n"},
	} {
		args := append([]string{"show"}, tt.options...)
		args = append(args, "libsecret:synthetic")
		var out, errOut bytes.Buffer
		if status := Main(args, nil, &out, &errOut); status != 0 || out.String() != "libsecret:synthetic\n"+tt.body || errOut.Len() != 0 {
			t.Errorf("legacy provider show changed: status %d stdout %q stderr %q", status, out.String(), errOut.String())
		}
	}
}
