package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Launch sources are analyzer input only, with metadata under a disposable HOME.
func TestAudit28LaunchDenoSpreadWitnesses(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, member := range []string{"Deno.Command", "globalThis.Deno /* hi */ .Command", "globalThis . Deno . Command"} {
		for _, options := range []string{
			`args:[%s]`, `args:[%s], ...{}`, `...{}, args:[%s]`,
			`...options, args:[%s], ...other`, `args:[%s], ...{env:{}}`,
			`args:[%s], [dynamic]:value`, `get other(){return {}}, args:[%s]`,
		} {
			for _, child := range []struct {
				name, args string
				deny       bool
			}{
				{"gh", `"auth","token"`, true}, {"env", `"gh","auth","token"`, true},
				{"cat", `"README.md"`, false}, {"echo", `"public"`, false},
			} {
				code := fmt.Sprintf(`new %s(%q,{%s}).spawn()`, member, child.name, fmt.Sprintf(options, child.args))
				for _, prefix := range [][]string{nil, {"env"}} {
					argv := append(append([]string{}, prefix...), "deno", "eval", code)
					if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != child.deny {
						t.Errorf("argv %q: deny=%v reason=%q", argv, child.deny, reason)
					}
					var quoted []string
					for _, arg := range argv {
						quoted = append(quoted, shellLiteral(arg))
					}
					if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != child.deny {
						t.Errorf("shell %s: deny=%v reason=%q", code, child.deny, reason)
					}
				}
			}
		}
	}
}

func TestAudit28LaunchPHPArrayCwd(t *testing.T) {
	home, work, check := audit21Fixture(t)
	aws := filepath.ToSlash(filepath.Join(home, ".aws"))
	if err := os.WriteFile(filepath.Join(home, ".aws", "public.txt"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, container := range []string{`[%s]`, `array(%s)`, `ARRAY /* literal argv */ (%s)`} {
		for _, child := range []struct {
			args string
			deny bool
		}{
			{`"cat","credentials"`, true}, {`"cat","public.txt"`, false},
			{`"gh","auth","token"`, true}, {`"echo","public"`, false},
			{`0=>"cat",1=>"credentials"`, true}, {`0=>"cat",1=>"public.txt"`, false},
			{`0=>"gh",1=>"auth",2=>"token"`, true}, {`0=>"echo",1=>"public"`, false},
			{`"cat",1 /* argv index */ => "credentials",`, true},
			{`0=>"cat","public.txt",`, false},
		} {
			code := fmt.Sprintf(`proc_open(%s,[0=>STDIN,1=>STDOUT,2=>STDERR],$pipes,%q);`, fmt.Sprintf(container, child.args), aws)
			stdin := "<?php\n" + code
			for _, source := range []string{
				"php -r " + shellLiteral(code),
				"php <<'SYNTHETIC'\n" + stdin + "\nSYNTHETIC",
				"php <<< " + shellLiteral(stdin),
				"printf '%s\\n' " + shellLiteral(stdin) + " | php",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: deny=%v reason=%q", source, child.deny, reason)
				}
			}
			if reason := AnalyzeArgv([]string{"php", "-r", code}, work, home, check); (reason != "") != child.deny {
				t.Errorf("argv %s: deny=%v reason=%q", code, child.deny, reason)
			}
		}
	}
	code := fmt.Sprintf(`proc_open(array("true"),[],$pipes,%q);`, aws)
	if reason := Analyze("php -r "+shellLiteral(code)+"; cat credentials", work, home, check); reason != "" {
		t.Errorf("PHP cwd escaped its child: %s", reason)
	}
}

func TestAudit28LaunchPHPArrayKeys(t *testing.T) {
	for _, tc := range []struct {
		args  string
		known bool
	}{
		{`"cat","public.txt"`, true},
		{`0=>"cat",1=>"public.txt"`, true},
		{`0=>"cat","public.txt",`, true},
		{`"cat",1 /* index */ => "public.txt"`, true},
		{`1=>"cat",2=>"public.txt"`, false},
		{`0=>"cat",0=>"public.txt"`, false},
		{`0=>"cat",2=>"public.txt"`, false},
		{`0=>"cat",1+0=>"public.txt"`, false},
		{`0=>"cat",$index=>"public.txt"`, false},
		{`0=>"cat",1=>$path`, false},
		{`0=>"cat",1=>"$path"`, false},
		{`0=>"cat",1=>"public.txt".$suffix`, false},
		{`0=>"cat",1=>`, false},
	} {
		for _, close := range []string{"]", ")"} {
			tokens := interpreterTokens(tc.args+close, "php")
			words, end, known := literalArrayArguments(tokens, 0, close, true)
			if known != tc.known {
				t.Errorf("%s%s: known=%v, want %v", tc.args, close, known, tc.known)
			}
			if known && (strings.Join(words, "|") != "cat|public.txt" || end != len(tokens)) {
				t.Errorf("%s%s: words=%q end=%d, want full literal argv", tc.args, close, words, end)
			}
			if strings.Contains(tc.args, "=>") {
				if _, _, known := literalArguments(tokens, 0, close); known {
					t.Errorf("PHP key syntax accepted outside PHP array parser: %s%s", tc.args, close)
				}
			}
		}
	}
}

func TestAudit28LaunchEnvSplitOperands(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("SYNTHETIC=fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{"-S%s", "--split-string=%s", "-S", "--split-string"} {
		for _, child := range []struct {
			value string
			tail  []string
			deny  bool
		}{
			{"cat", []string{".env"}, true}, {"gh", []string{"auth", "token"}, true},
			{"timeout 5", []string{"cat", ".env"}, true}, {"env", []string{"gh", "auth", "token"}, true},
			{"cat", []string{"README.md"}, false}, {"cat", []string{".env.example"}, false},
			{"echo", []string{"$(gh auth token)", "`gh auth token`", "public'quote", "public\nline"}, false},
		} {
			argv := []string{"env"}
			if strings.Contains(form, "%s") {
				argv = append(argv, fmt.Sprintf(form, child.value))
			} else {
				argv = append(argv, form, child.value)
			}
			argv = append(argv, child.tail...)
			if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != child.deny {
				t.Errorf("argv %q: deny=%v reason=%q", argv, child.deny, reason)
			}
			var quoted []string
			for _, arg := range argv {
				quoted = append(quoted, shellLiteral(arg))
			}
			if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != child.deny {
				t.Errorf("shell %q: deny=%v reason=%q", argv, child.deny, reason)
			}
		}
	}
}

func TestAudit28LaunchSystemdEnvironment(t *testing.T) {
	home, work, check := audit21Fixture(t)
	custom := filepath.ToSlash(filepath.Join(work, "custom.cfg"))
	if err := os.WriteFile(filepath.Join(work, "custom.cfg"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "SYNTHETIC"} {
		for _, attached := range []bool{false, true} {
			for _, child := range [][]string{{"cat", custom}, {"head", "-n", "1", custom}, {"sed", "-n", "1p", custom}, {"cat", "README.md"}} {
				argv := []string{"systemd-run", "--user", "--pipe", "--wait"}
				if attached {
					argv = append(argv, "--setenv="+key+"="+custom)
				} else {
					argv = append(argv, "--setenv", key+"="+custom)
				}
				argv = append(argv, child...)
				deny := key != "SYNTHETIC" && child[len(child)-1] == custom
				if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != deny {
					t.Errorf("argv %q: deny=%v reason=%q", argv, deny, reason)
				}
				var quoted []string
				for _, arg := range argv {
					quoted = append(quoted, shellLiteral(arg))
				}
				if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != deny {
					t.Errorf("shell %q: deny=%v reason=%q", argv, deny, reason)
				}
			}
		}
	}
	for _, source := range []string{
		"systemd-run --setenv=KUBECONFIG=custom.cfg true; cat custom.cfg",
		"systemd-run --setenv KUBECONFIG=custom.cfg true; cat custom.cfg",
		"systemd-run --setenv=AWS_CONFIG_FILE=custom.cfg true; cat custom.cfg",
		"systemd-run --setenv=KUBECONFIG=custom.cfg true; systemd-run cat custom.cfg",
		"systemd-run --setenv SYNTHETIC cat custom.cfg",
		"systemd-run --setenv=SYNTHETIC cat custom.cfg",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("configured environment escaped child scope %s: %s", source, reason)
		}
	}
	for _, source := range []string{
		"systemd-run --setenv=KUBECONFIG=custom.cfg --working-directory . cat custom.cfg",
		"systemd-run --working-directory . --setenv AWS_CONFIG_FILE=custom.cfg cat custom.cfg",
		"systemd-run --setenv KUBECONFIG=custom.cfg --setenv SYNTHETIC=yes cat custom.cfg",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("configured cwd/repeated option allowed: %s", source)
		}
	}
}

func TestAudit28LaunchMalformedWrappers(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"timeout 5", true}, {"gtimeout -s TERM 5", true},
		{"taskset 0x1", true}, {"taskset -ac 0", true},
		{"taskset not-a-mask true", true}, {"taskset -c not-a-list true", true},
		{"taskset -c 0- true", true}, {"taskset 0x true", true},
		{"setsid --synthetic-unknown true", true}, {"setsid --wait=yes true", true},
		{"setsid -z true", true},
		{"timeout 5 true", false}, {"gtimeout -s TERM 5 true", false},
		{"timeout --kill-after=1 5 true", false}, {"taskset 0x1 true", false},
		{"taskset -ac 0 true", false}, {"taskset --cpu-list 0,2 true", false},
		{"taskset -c 0-3:2,5 true", false}, {"taskset f true", false},
		{"taskset -p 123", false}, {"taskset -cp 123", false},
		{"chrt -p 123", false},
		{"setsid true", false}, {"setsid --wait true", false},
		{"setsid -f -- true", false}, {"setsid --ctty --fork true", false},
		{"timeout 5 cat ~/.aws/credentials", true}, {"taskset -ac 0 gh auth token", true},
		{"setsid --wait gh auth token", true},
	} {
		for _, prefix := range []string{"", "env "} {
			if reason := Analyze(prefix+tc.source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("%s: deny=%v reason=%q", prefix+tc.source, tc.deny, reason)
			}
			if reason := AnalyzeArgv(strings.Fields(prefix+tc.source), work, home, check); (reason != "") != tc.deny {
				t.Errorf("argv %s: deny=%v reason=%q", prefix+tc.source, tc.deny, reason)
			}
		}
	}
}
