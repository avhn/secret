//go:build windows

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/testutil"
)

func TestWindowsHomeRejectsAmbiguousOverrides(t *testing.T) {
	t.Setenv("HOME", testutil.TempDir(t))
	for _, overrides := range [][2]string{
		{`C:relative`, `C:\synthetic.env`},
		{`C:\synthetic`, `C:relative`},
		{`C:\synthetic`, `C:\synthetic.env:stream`},
	} {
		t.Setenv("SECRETS_DIR", overrides[0])
		t.Setenv("SECRETS_ENV", overrides[1])
		var out, diagnostic strings.Builder
		if status := Main([]string{"list"}, os.Stdin, &out, &diagnostic); status != 1 || out.Len() != 0 || diagnostic.String() != "secret: invalid keystore name\n" {
			t.Fatal("ambiguous store override was not rejected before discovery")
		}
	}
}

func TestWindowsNativeHomeSubprocess(t *testing.T) {
	if os.Getenv("SECRET_TEST_NATIVE_HOME_CHILD") == "1" {
		os.Exit(Main([]string{"list"}, os.Stdin, os.Stdout, os.Stderr))
	}
	for _, explicit := range []bool{false, true} {
		name := "USERPROFILE fallback"
		if explicit {
			name = "explicit store overrides without profile"
		}
		t.Run(name, func(t *testing.T) {
			home := testutil.TempDir(t)
			dir := filepath.Join(home, ".secrets")
			envFile := filepath.Join(home, ".secrets.env")
			if explicit {
				dir = filepath.Join(home, "override")
				envFile = filepath.Join(home, "override.env")
			}
			if err := testutil.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "synthetic.secret")
			for _, file := range []string{path, envFile} {
				if err := testutil.WriteFile(file, []byte("TOKEN=synthetic-home-test\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestWindowsNativeHomeSubprocess$")
			for _, item := range os.Environ() {
				key, _, _ := strings.Cut(item, "=")
				switch strings.ToUpper(key) {
				case "HOME", "USERPROFILE", "SECRETS_DIR", "SECRETS_ENV", "SECRET_TEST_NATIVE_HOME_CHILD":
					continue
				}
				cmd.Env = append(cmd.Env, item)
			}
			cmd.Env = append(cmd.Env, "SECRET_TEST_NATIVE_HOME_CHILD=1")
			if explicit {
				cmd.Env = append(cmd.Env, "SECRETS_DIR="+dir, "SECRETS_ENV="+envFile)
			} else {
				cmd.Env = append(cmd.Env, "USERPROFILE="+home)
			}
			output, err := cmd.CombinedOutput()
			if err != nil || string(output) != envFile+"\n"+path+"\n" {
				t.Fatalf("native home subprocess failed: %v (output omitted)", err)
			}
		})
	}
}
