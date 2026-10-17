package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestAudit20PrintersAndSinks(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KUBECONFIG", "")
	check := func(string, string) bool { return false }
	for _, source := range []string{
		"aws --cli-binary-format raw-in-base64-out ecr get-login-password",
		"aws --cli-auto-prompt off ecr get-login-password",
		"aws ecr --unknown z get-login-password",
		"aws sts --cli-binary-format raw-in-base64-out get-session-token",
		"aws --color on ecr get-login-password",
		"aws --no-sign-request ecr get-login-password",
		"aws --color off ecr get-login-password",
		"aws --no-cli-auto-prompt ecr get-login-password",
		"gcloud --billing-project synthetic auth print-access-token",
		"doctl -c synthetic auth token",
		"kubectl --request-timeout=30s create token synthetic",
		"aws ecr-public get-login-password", "aws ecr get-authorization-token",
		"aws sts assume-role", "aws sts assume-role-with-web-identity",
		"aws sts assume-role-with-saml", "aws sts get-federation-token",
		"gcloud --unknownflag=1 auth print-access-token",
		"vault --unknown x print token",
		"heroku --unknown auth:token",
		"glab --unknown auth status --show-token",
		"az account --subscription s get-access-token",
		"doctl --trace auth token",
	} {
		t.Run(source, func(t *testing.T) {
			if reason := AnalyzeArgv(strings.Fields(source), root, root, check); reason == "" {
				t.Error("argv printer allowed")
			}
			for _, variant := range deniedVariants(source) {
				if reason := Analyze(variant, root, root, check); reason == "" {
					t.Errorf("printer allowed: %s", variant)
				}
			}
			for _, sink := range []struct {
				source string
				deny   bool
			}{
				{"docker login --password-stdin r.example", false},
				{"helm registry login --password-stdin r.example", false},
				{"secret stash synthetic TOKEN", false},
				{"docker run -i alpine cat", true},
				{"docker --password-stdin run -i alpine cat", true},
				{"helm --password-stdin template x", true},
				{"cat | docker login --password-stdin r.example", true},
				{"tee capture | helm registry login --password-stdin r.example", true},
				{"docker login --password-stdin < README.md", true},
			} {
				if reason := Analyze(source+" | "+sink.source, root, root, check); (reason != "") != sink.deny {
					t.Errorf("%s: reason=%q, deny=%v", sink.source, reason, sink.deny)
				}
			}
		})
	}
	for _, source := range []string{
		"aws s3 ls", "aws --profile p s3 ls", "gcloud auth list",
		"az account show", "kubectl get pods",
		"aws ecr get-login-password | docker login --password-stdin r.example",
		"aws ecr get-login-password | helm registry login --password-stdin r.example",
	} {
		if reason := Analyze(source, root, root, check); reason != "" {
			t.Errorf("safe command %q: %s", source, reason)
		}
	}
}

func TestAudit20AliasesAndSubshells(t *testing.T) {
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{filepath.Join(home, ".aws"), filepath.Join(work, "src")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".aws", "credentials"), filepath.Join(work, ".env"), filepath.Join(work, "README.md")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	check := func(name, cwd string) bool {
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, cwd, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return paths.Protected(name, cwd, "", home)
	}
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"alias c=cd\nc ~/.aws\ncat credentials", true},
		{"eval 'alias c=cd'\nc ~/.aws\ncat credentials", true},
		{"eval \"alias c='cd ~/.aws'\"\nc\ncat credentials", true},
		{"builtin alias c=cd\nc ~/.aws\ncat credentials", true},
		{"alias c='echo ok; cd ~/.aws'\nc\ncat credentials", true},
		{"alias c=pushd\nc ~/.aws\ncat credentials", true},
		{"alias c=popd\nc\ncat credentials", true},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand c\ncat credentials", true},
		{"alias c='echo ok; f'\nf() { cd ~/.aws; }\ncommand c\ncat credentials", true},
		{"alias c=f\nf() { cd ~/.aws; }\nbuiltin c\ncat credentials", true},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand -p -- c\ncat credentials", true},
		{"alias c=next\nalias next=f\nf() { cd ~/.aws; }\ncommand c\ncat credentials", true},
		{"alias c='$MOVE'\ncommand c\ncat credentials", true},
		{"alias c='('\ncommand c\ncat credentials", true},
		{"alias c=\"$D\"\nc ~/.aws\ncat credentials", true},
		{"alias c='$D'\nc ~/.aws\ncat credentials", true},
		{"alias r=cat\nr ~/.aws/credentials", true},
		{"alias r='cat ~/.aws/credentials'\nr", true},
		{"alias r='echo ok; cat ~/.aws/credentials'\nr", true},
		{"alias r='cat ~/.aws/credentials'\nr | docker login --password-stdin", true},
		{"eval \"alias r='head ~/.aws/credentials'\"\nr", true},
		{"alias r='head ~/.aws/credentials'\nalias s=r\ns", true},
		{"alias r='cat ~/.aws/credentials'\nalias r='ls -l'\nr", true},
		{"alias r='cat ~/.aws/credentials'\nf() { r; }; f", true},
		{"alias r='cat ~/.aws/credentials'\neval r", true},
		{"alias ll='ls -l'\nll src", false},
		{"eval \"alias ll='ls -l'\"\nll src", false},
		{"alias cat='cat -n'\ncat README.md", false},
		{"alias ll='ls -l'\nll src\ncat README.md", false},
		{"alias ll='ls -l'\ncommand ll src\ncat README.md", false},
		{"alias ll='ls -l'\nbuiltin ll src\ncat README.md", false},
		{"alias cat='cat -n'\ncommand cat README.md", false},
		{"alias ls='ls -l'\ncommand ls\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand -v c\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand -V c\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand ls\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\n(command c)\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand c &\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand c | true\ncat credentials", false},
		{"alias c=f\nf() { cd ~/.aws; }\ncommand c < .env", true},
		{"(alias c=cd)\ncat credentials", false},
		{"alias c=cd &\ncat credentials", false},
		{"alias c=cd | true\ncat credentials", false},
		{"f() { alias c=cd; }; cat credentials", false},
		{"eval '(cd ~/.aws)'; cat credentials", false},
		{"eval 'echo $(cd ~/.aws)'; cat credentials", false},
		{"eval 'echo $CODE'; cat credentials", true},
		{"eval 'echo $((CDPATH=1))'; cat credentials", true},
		{"eval 'echo $(cd ~/.aws; cat credentials)'", true},
		{"eval '(cd ~/.aws; cat credentials)'", true},
		{"eval 'cd ~/.aws'; cat credentials", true},
		{"eval 'echo $(alias c=cd)'; cat credentials", false},
		{"eval '(alias c=cd)'; cat credentials", false},
	} {
		t.Run(tc.source, func(t *testing.T) {
			if reason := Analyze(tc.source, work, home, check); (reason != "") != tc.deny {
				t.Errorf("reason=%q, deny=%v", reason, tc.deny)
			}
		})
	}
}

func TestAudit20InterpreterCredentialLiterals(t *testing.T) {
	root := t.TempDir()
	home, work := filepath.Join(root, "home"), filepath.Join(root, "work")
	for _, dir := range []string{filepath.Join(home, ".kube"), work} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".yarnrc.yml"), filepath.Join(home, ".kube", "config"), filepath.Join(work, "custom.cfg")} {
		if err := os.WriteFile(name, []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", home) }
	for _, tc := range []struct {
		prefix, name string
		deny         bool
	}{
		{"", "$HOME/.yarnrc.yml", true},
		{"", "$HOME/.kube/config", true},
		{"KUBECONFIG=custom.cfg ", "custom.cfg", true},
		{"KUBECONFIG=custom.cfg ", "./custom.cfg", true},
		{"cd ~/.kube; ", "config", true},
		{"AWS_CONFIG_FILE=custom.cfg ", "custom.cfg", true},
		{"AWS_SHARED_CREDENTIALS_FILE=custom.cfg ", "./custom.cfg", true},
		{"", "README.md", false},
		{"", ".yarnrc.yml", false},
	} {
		for _, command := range []string{"python3", "node", "ruby", "perl"} {
			flag, body := "-e", ""
			switch command {
			case "python3":
				flag, body = "-c", `print(open("`+tc.name+`").read())`
			case "node":
				body = `console.log(require("fs").readFileSync("` + tc.name + `", "utf8"))`
			case "ruby":
				body = `puts File.read("` + tc.name + `")`
			case "perl":
				body = `open my $f, "<", "` + tc.name + `"; print <$f>`
			}
			pipePrefix := tc.prefix
			if strings.Contains(pipePrefix, "=") && !strings.Contains(pipePrefix, ";") {
				pipePrefix = strings.TrimSpace(pipePrefix) + "; "
			}
			for _, source := range []string{
				tc.prefix + command + " " + flag + " '" + body + "'",
				tc.prefix + command + " <<'BODY'\n" + body + "\nBODY",
				pipePrefix + "printf '%s' '" + body + "' | " + command,
				pipePrefix + "cat <<'BODY' | " + command + "\n" + body + "\nBODY",
				tc.prefix + command + " <<'BODY'\n" + strings.Repeat("# synthetic padding\n", 500) + body + "\nBODY",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s %s: reason=%q, deny=%v", command, tc.name, reason, tc.deny)
				}
			}
		}
	}
	if reason := Analyze("python3 - <<'BODY'\n"+strings.Repeat("a", 11000)+"\nBODY", work, home, check); reason != "" {
		t.Errorf("inert oversized interpreter body: %s", reason)
	}
	t.Setenv("KUBECONFIG", "absent.cfg")
	for _, source := range []string{`python3 -c 'print(open("absent.cfg").read())'`, "python3 <<'BODY'\nprint(open('absent.cfg').read())\nBODY", `python3 <<< 'open("absent.cfg")'`, `printf '%s' 'open("absent.cfg")' | python3`} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Error("inherited configured interpreter credential allowed")
		}
	}
}

func TestAudit20ConfiguredHistoricalGit(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2, "README.md")
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{"KUBECONFIG=custom.cfg; git show HEAD~1:custom.cfg", true},
		{"KUBECONFIG=custom.cfg; git cat-file -p HEAD~1:custom.cfg", true},
		{"KUBECONFIG=custom.cfg; git log -p HEAD~1:custom.cfg", true},
		{"KUBECONFIG=custom.cfg; git log --oneline HEAD~1:custom.cfg", true},
		{"git diff --stat HEAD~1:.env.production HEAD:README.md", true},
		{"git diff --name-only HEAD~1:.env.production HEAD:README.md", true},
		{"AWS_CONFIG_FILE=custom.cfg; git show HEAD~1:custom.cfg", true},
		{"AWS_SHARED_CREDENTIALS_FILE=custom.cfg; git log --oneline HEAD~1:custom.cfg", true},
		{"git log --grep=HEAD~1:.env.production", false},
		{"git log --grep HEAD~1:.env.production", false},
		{"git diff --stat HEAD~1:.env.example HEAD:README.md", false},
		{"KUBECONFIG=custom.cfg; git log --oneline HEAD~1:README.md", false},
	} {
		for _, source := range deniedVariants(tc.source) {
			if reason := Analyze(source, root, root, check); (reason != "") != tc.deny {
				t.Errorf("%s: reason=%q, deny=%v", source, reason, tc.deny)
			}
		}
	}
}

func TestAudit20AWSConfigAssignments(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"custom.cfg", "README.md"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("synthetic"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	for _, key := range []string{"AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		for _, source := range []string{
			key + "=custom.cfg; cat custom.cfg",
			key + "=custom.cfg cat custom.cfg",
			key + "=custom.cfg; find . -name '*.cfg' | xargs cat",
			key + "=custom.cfg; fd -g '*.cfg' -x cat",
			key + "=custom.cfg; rg -g '*.cfg' TOKEN",
			"if true; then " + key + "=custom.cfg; else " + key + "=README.md; fi; cat custom.cfg",
		} {
			if reason := Analyze(source, root, root, check); reason == "" {
				t.Errorf("configured AWS credential allowed: %s", source)
			}
		}
	}
	for _, source := range []string{"aws configure list", "aws s3 ls", "aws --profile p sts get-caller-identity"} {
		if reason := Analyze(source, root, root, check); reason != "" {
			t.Errorf("public AWS metadata %q: %s", source, reason)
		}
	}
}

func TestAudit20NativeAbsoluteUnknownCwd(t *testing.T) {
	root := t.TempDir()
	t.Setenv("KUBECONFIG", "")
	t.Setenv("AWS_CONFIG_FILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
	a := analyzer{home: root, protected: func(string, string) bool { return false }}
	file := filepath.ToSlash(filepath.Join(root, "README.md"))
	if a.inputProtected(file, "") {
		t.Errorf("native absolute public file became relative under uncertain cwd: %s", file)
	}
	if a.resolve(file, "") != file {
		t.Error("native absolute file was reanchored")
	}
	if !a.inputProtected("README.md", "") {
		t.Error("relative file lost uncertain-cwd protection")
	}
}
