package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// All source below is analyzer input, never executable test code.
func TestAudit25LaunchDeadline(t *testing.T) {
	home, work, check := audit21Fixture(t)
	a := &analyzer{home: home, cwd: work, protected: check, deadline: time.Now().Add(-time.Second)}
	if !a.interpreterArgvProtected(`new Deno.Command("echo",{args:["public"]})`, work, "deno") || a.reason == "" {
		t.Fatal("literal argv scan ignored the shared deadline")
	}
}

func TestAudit25FallbackCommandRoles(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, "custom.cfg"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, child := range []struct {
		code string
		deny bool
	}{
		{"unzip -p fixture.zip", true}, {"7z x -so fixture.zip", true},
		{"cpio -i --to-stdout -F fixture.cpio", true}, {"gmake -p", true},
		{"busybox tar xOf fixture.tar", true}, {"toybox tar xOf fixture.tar", true},
		{"env unknown gh auth token", true}, {"nice -n 1 unknown gh auth token", true},
		{"unzip -l fixture.zip", false}, {"7z l fixture.zip", false},
		{"cpio -t -F fixture.cpio", true}, // Unmodeled options stay indeterminate.
		{"cpio -t fixture.cpio", false}, {"gmake public", false},
		{"busybox tar tf fixture.tar", false}, {"toybox tar tf fixture.tar", false},
		{"ordinary public prose", false}, {"don't parse this prose", false},
		{"not env", false}, {"hi [[ public ]] bye", false},
		{"echo public", false}, {"cat README.md", false},
		{"export KUBECONFIG=custom.cfg; cat custom.cfg", true},
		{"find ~/.aws -type f | parallel cat", true},
		{"export -p", true}, {"cd ~/.aws; cat credentials", true},
		{"printenv", true}, {"true", false},
		{"export SYNTHETIC=public; cat README.md", false},
		{"export KUBECONFIG=custom.cfg; cat README.md", false},
		{"cd sub; cat ../README.md", false},
		{"find sub -type f | parallel cat", false},
	} {
		for _, program := range []string{"lua", "lua5.4", "luajit"} {
			for _, value := range []string{fmt.Sprintf("%q", child.code), "[[" + child.code + "]]", "[==[" + child.code + "]==]"} {
				code := "os.execute(" + value + ")"
				for _, source := range []string{
					program + " -e " + shellLiteral(code),
					program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
					program + " <<< " + shellLiteral(code),
				} {
					if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
					}
				}
				if reason := AnalyzeArgv([]string{program, "-e", code}, work, home, check); (reason != "") != child.deny {
					t.Errorf("argv %s %s: reason=%q want deny=%v", program, code, reason, child.deny)
				}
			}
		}
	}
}

func TestAudit25StructuredLaunchArguments(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, api := range []struct{ program, flag, code string }{
		{"ruby", "-e", `exec(["%s","display"],%s)`},
		{"ruby", "-e", `exec ["%s","display"],%s`},
		{"ruby", "-e", `system(["%s","display"],%s)`},
		{"ruby", "-e", `Process.spawn(["%s","display"],%s)`},
		{"php", "-r", `proc_open(["%s",%s],[1=>STDOUT,2=>STDERR],$pipes);`},
		{"deno", "eval", `new Deno.Command("%s",{args:[%s],stdout:"inherit"}).outputSync();`},
		{"deno", "eval", `new Deno.Command("%s",{"stdout":"inherit","args":[%s]}).spawn();`},
		{"deno", "eval", "new Deno.Command(`%s`,{cwd:'.',args:[%s]}).spawn();"},
		{"deno", "eval", `const env = {}; new Deno.Command("%s",{args:[%s],stdout:"inherit",env}).outputSync();`},
		{"deno", "eval", `const env = {}; new Deno.Command("%s",{env,args:[%s],stdout:"inherit"}).outputSync();`},
		{"deno", "eval", `const env = {}; const cwd = "."; new Deno.Command("%s",{env,args:[%s],cwd,}).spawn();`},
	} {
		for _, child := range []struct {
			name, args string
			deny       bool
		}{
			{"gh", `"auth","token"`, true}, {"cat", `".env"`, true},
			{"git", `"status"`, false}, {"cat", `"README.md"`, false},
			{"echo", `"public"`, false},
		} {
			code := fmt.Sprintf(api.code, child.name, child.args)
			stdin := code
			if api.program == "php" {
				stdin = "<?php\n" + code
			}
			program := api.program
			if program == "deno" {
				program += " run --allow-run -"
			}
			for _, source := range []string{
				api.program + " " + api.flag + " " + shellLiteral(code),
				program + " <<'SYNTHETIC'\n" + stdin + "\nSYNTHETIC",
				program + " <<< " + shellLiteral(stdin),
				"printf '%s\\n' " + shellLiteral(stdin) + " | " + program,
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != child.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, child.deny)
				}
			}
			if reason := AnalyzeArgv([]string{api.program, api.flag, code}, work, home, check); (reason != "") != child.deny {
				t.Errorf("argv %s: reason=%q want deny=%v", code, reason, child.deny)
			}
		}
	}
	for _, code := range []string{
		`exec ["printenv","display"]`, `exec(["printenv","display"])`,
	} {
		if reason := AnalyzeArgv([]string{"ruby", "-e", code}, work, home, check); reason == "" {
			t.Errorf("pair-only executable lost its role: %s", code)
		}
	}
	for _, code := range []string{
		`new Deno.Command("gh",{args:["auth","token"],args:["help"]})`,
		`new Deno.Command("gh",{other:{args:["help"]},args:["auth","token"]})`,
		`new Deno.Command("gh",{args : ["auth", "token"], stdout : "inherit"})`,
	} {
		if reason := AnalyzeArgv([]string{"deno", "eval", code}, work, home, check); reason == "" {
			t.Errorf("constructor lost literal args witness: %s", code)
		}
	}
	for _, tc := range []struct{ program, flag, code string }{
		{"ruby", "-e", `puts 'exec(["gh","display"],"auth","token")'`},
		{"ruby", "-e", `# exec(["gh","display"],"auth","token")`},
		{"php", "-r", `echo 'proc_open(["gh","auth","token"],[],$pipes)';`},
		{"php", "-r", `// proc_open(["gh","auth","token"],[],$pipes)`},
		{"deno", "eval", `console.log('new Deno.Command("gh",{args:["auth","token"]})')`},
		{"deno", "eval", `// new Deno.Command("gh",{args:["auth","token"]})`},
		{"deno", "eval", `new Deno.Command("echo",{args:["public"],other:{args:["auth","token"]}})`},
	} {
		if reason := AnalyzeArgv([]string{tc.program, tc.flag, tc.code}, work, home, check); reason != "" {
			t.Errorf("inert launch syntax %s: %s", tc.code, reason)
		}
	}
}

func TestAudit25SudoAssignments(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, "custom.cfg"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, wrapper := range []string{"sudo -n", "sudo --non-interactive --", "sudo -u synthetic", "nice -n 1 sudo -n", "timeout 2 sudo -n", "env SYNTHETIC=yes sudo -n"} {
		for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
			for _, reader := range []string{"cat custom.cfg", "head custom.cfg", `python3 -c 'open("custom.cfg").read()'`, `node -e 'require("fs").readFileSync("custom.cfg")'`, `perl -e 'open my $f,"custom.cfg"'`} {
				source := wrapper + " " + key + "=custom.cfg " + reader
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("configured sudo child allowed: %s", source)
				}
			}
			argv := append(strings.Fields(wrapper), key+"=custom.cfg", "cat", "custom.cfg")
			if reason := AnalyzeArgv(argv, work, home, check); reason == "" {
				t.Errorf("configured sudo argv child allowed: %q", argv)
			}
		}
	}
	for _, source := range []string{
		"sudo -n SYNTHETIC=yes cat custom.cfg",
		"sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg",
		"sudo -n AWS_CONFIG_FILE=custom.cfg true; cat custom.cfg",
		"sudo -n KUBECONFIG=custom.cfg echo public; sudo -n cat custom.cfg",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("sudo assignment escaped child scope %s: %s", source, reason)
		}
	}
}

func TestAudit25ParallelProducerScope(t *testing.T) {
	home, work, check := audit21Fixture(t)
	if err := os.WriteFile(filepath.Join(work, "custom.cfg"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, consumer := range []string{"env KUBECONFIG=custom.cfg parallel cat", "sudo -n AWS_CONFIG_FILE=custom.cfg parallel cat", "KUBECONFIG=custom.cfg xargs cat"} {
		if reason := Analyze("find . -type f | "+consumer, work, home, check); reason == "" {
			t.Errorf("consumer assignment lost during producer proof: %s", consumer)
		}
	}
	for _, producer := range []string{
		"find ~/.aws -type f", "find ~/.aws -type f -print0",
		"rg --files --hidden --no-ignore ~/.aws", "fd --hidden --no-ignore --type f . ~/.aws",
		"find ~/.aws -type f | sort", "find \"$UNKNOWN\" -type f",
	} {
		for _, consumer := range []string{"parallel cat", "parallel -0 cat", "parallel --will-cite head", "env SYNTHETIC=yes parallel cat", "xargs cat"} {
			if reason := Analyze(producer+" | "+consumer, work, home, check); reason == "" {
				t.Errorf("protected producer allowed: %s | %s", producer, consumer)
			}
		}
	}
	for _, source := range []string{
		"find sub -type f | parallel cat", "find sub -type f -print0 | parallel -0 cat",
		"fd --type f . sub | parallel cat", "rg --files sub | parallel cat",
		"find ~/.aws -type f | parallel stat", "find ~/.aws -type f | parallel cat ::: README.md",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("safe producer/consumer denied %s: %s", source, reason)
		}
	}
}

func TestAudit25RepeatedExecutableOptions(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, command := range []struct{ program, option, safe, unsafe string }{
		{"make", "--eval", "audit:; echo public", "audit:; printenv TOKEN"},
		{"gmake", "-E", "audit:; echo public", "audit:; printenv TOKEN"},
		{"make", "-sE", "audit:; echo public", "audit:; gh auth token"},
		{"gmake", "-nsE", "audit:; echo public", "audit:; gh auth token"},
		{"rsync", "-e", "echo public", "printenv TOKEN"},
		{"rsync", "-aze", "echo public", "gh auth token"},
		{"su", "-c", "echo public", "printenv TOKEN"},
		{"runuser", "--command", "echo public", "printenv TOKEN"},
		{"npm exec", "--call", "echo public", "printenv TOKEN"},
		{"npx", "-c", "echo public", "gh auth token"},
	} {
		for _, attached := range []bool{false, true} {
			for _, deny := range []bool{false, true} {
				last := command.safe
				if deny {
					last = command.unsafe
				}
				argv := strings.Fields(command.program)
				for _, value := range []string{command.safe, last} {
					if attached {
						option := command.option
						if strings.HasPrefix(option, "--") {
							option += "="
						}
						argv = append(argv, option+value)
					} else {
						argv = append(argv, command.option, value)
					}
				}
				var source []string
				for _, arg := range argv {
					source = append(source, shellLiteral(arg))
				}
				if reason := Analyze(strings.Join(source, " "), work, home, check); (reason != "") != deny {
					t.Errorf("%s: reason=%q want deny=%v", strings.Join(source, " "), reason, deny)
				}
				if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != deny {
					t.Errorf("argv %q: reason=%q want deny=%v", argv, reason, deny)
				}
			}
		}
	}
	for _, source := range []string{"make --eval 'audit:; echo public' --eval", "rsync -e 'echo public' -e", "npm exec --call 'echo public' --call", "make --eval 'audit:; echo public' -f /dev/stdin", "make --eval 'public:; echo ok' -sE", "gmake -E 'public:; echo ok' -nsE"} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("missing repeated slot value allowed: %s", source)
		}
	}
}
