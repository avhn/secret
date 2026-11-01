package cli

import (
	"bytes"
	"testing"
)

func TestVersionAliases(t *testing.T) {
	previous := Version
	Version = "0.5.0"
	t.Cleanup(func() { Version = previous })
	for _, test := range []struct {
		name   string
		args   []string
		status int
		out    string
		err    string
	}{
		{"subcommand", []string{"version"}, 0, "secret 0.5.0 (go)\n", ""},
		{"flag", []string{"--version"}, 0, "secret 0.5.0 (go)\n", ""},
		{"subcommand arguments", []string{"version", "extra"}, 1, "", "secret: version takes no arguments\n"},
		{"flag arguments", []string{"--version", "extra"}, 1, "", "secret: version takes no arguments\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			status := Main(test.args, nil, &out, &errOut)
			if status != test.status || out.String() != test.out || errOut.String() != test.err {
				t.Fatalf("status=%d stdout=%q stderr=%q", status, out.String(), errOut.String())
			}
		})
	}
}
