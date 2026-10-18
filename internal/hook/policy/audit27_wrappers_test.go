package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Candidates are analyzer input only. All files live beneath a disposable HOME.
func TestAudit27XargsFilenameInputs(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for name, body := range map[string]string{
		".env": "SYNTHETIC=fixture\n", "names": ".env\n", "names0": ".env\x00",
		"external-names": filepath.ToSlash(filepath.Join(work, ".env")) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{"-a names", "--arg-file=names", "-anames", "-0 -a names0", "-a names -I{}"} {
		for _, child := range []string{"cat", "env cat", "timeout 5 cat", "nice -n 5 head", "busybox cat", "env -- timeout 5 cat", "unknown cat"} {
			argv := strings.Fields("xargs " + input + " " + child)
			if strings.Contains(input, "-I{}") {
				argv = append(argv, "{}")
			}
			if reason := AnalyzeArgv(argv, work, home, check); reason == "" {
				t.Errorf("argument-file argv allowed: %q", argv)
			}
			if reason := Analyze(strings.Join(argv, " "), work, home, check); reason == "" {
				t.Errorf("argument-file shell allowed: %q", argv)
			}
		}
	}
	// Keep pre-existing conservative scope denials while adding the separate
	// file-input proof for metadata children in clean directories.
	for _, source := range []string{"xargs busybox stat", "xargs env -C . stat", "find . -exec busybox stat {} +"} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("existing scope denial loosened: %s", source)
		}
	}
	clean := filepath.Join(work, "sub")
	for _, redirect := range []string{" < ../external-names", " <<<'public.txt'", " <<'NAMES'\npublic.txt\nNAMES"} {
		for _, child := range []string{"cat", "env cat", "timeout 5 head", "busybox cat"} {
			for _, source := range []string{"xargs " + child + redirect, "env xargs " + child + redirect, "{ xargs " + child + "; }" + redirect} {
				if reason := Analyze(source, clean, home, check); reason == "" {
					t.Errorf("redirected filename input allowed: %s", source)
				}
			}
		}
	}
	for _, source := range []string{
		"xargs env stat < ../external-names", "xargs timeout 5 stat < ../external-names",
		"xargs busybox stat < ../external-names", "xargs -a ../names env stat",
		"xargs env -C . stat < ../external-names", "xargs -a ../names env --chdir=. stat",
		"xargs cat 3< ../external-names",
		"xargs -a ../names env printf public", "xargs cat", "true < ../external-names; xargs cat",
		"find . -name '*.ts' | xargs env cat",
	} {
		if reason := Analyze(source, clean, home, check); reason != "" {
			t.Errorf("safe control %s: %s", source, reason)
		}
	}
}

func TestAudit27LauncherDirectories(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, dir := range []string{filepath.Join(home, ".aws"), work} {
		deny := dir != work
		quoted := shellLiteral(filepath.ToSlash(dir))
		for _, launcher := range []string{
			"uv run --directory " + quoted + " --no-project --no-sync ",
			"uv run --directory=" + quoted + " --no-project --no-sync ",
			"uv --directory " + quoted + " run --no-project --no-sync ",
			"uv --directory=" + quoted + " run --no-project --no-sync -- ",
			"systemd-run --user --pipe --wait --working-directory " + quoted + " ",
			"systemd-run --user --pipe --wait --working-directory=" + quoted + " ",
		} {
			for _, prefix := range []string{"", "env "} {
				for _, child := range []string{"cat credentials", "env cat credentials"} {
					source := prefix + launcher + child
					// The pre-existing opaque systemd fallback denies an env child
					// even on public input. This task must not loosen that denial.
					wantDeny := deny || strings.HasPrefix(launcher, "systemd-run") && strings.HasPrefix(child, "env ")
					if reason := Analyze(source, work, home, check); (reason != "") != wantDeny {
						t.Errorf("%s: deny=%v reason=%q", source, wantDeny, reason)
					}
				}
			}
		}
		for _, argv := range [][]string{
			{"uv", "run", "--directory", dir, "--no-project", "--no-sync", "cat", "credentials"},
			{"env", "uv", "--directory=" + dir, "run", "cat", "credentials"},
			{"systemd-run", "--user", "--pipe", "--working-directory", dir, "cat", "credentials"},
		} {
			if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != deny {
				t.Errorf("argv %q: deny=%v reason=%q", argv, deny, reason)
			}
		}
	}
	for _, source := range []string{
		"uv run --directory", "uv --directory", "systemd-run --working-directory",
		"systemd-run --description 'gh auth token' true",
		"systemd-run --description .env true",
		"uv run --directory .git true",
	} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("required launcher denial lost: %s", source)
		}
	}
	for _, source := range []string{
		"uv run --directory ~/.aws --no-project --no-sync true; cat credentials",
		"systemd-run --user --pipe --working-directory ~/.aws true; cat credentials",
		"uv run --directory sub --no-project --no-sync cat ../README.md",
		"uv run --directory ~/.aws --no-project --no-sync stat credentials",
		"systemd-run --user --pipe --working-directory ~/.aws stat credentials",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("child-local cwd control %s: %s", source, reason)
		}
	}
}

func TestAudit27UVOptionForms(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, options := range []string{
		"-p3.12", "-p=3.12", "--only-group test", "--only-group=test",
		"-qvp3.12", "-Cbuild.option=synthetic", "-wpytest", "-f./sub",
		"-ihttps://synthetic.invalid/simple", "-Ppytest", "--no-extra optional",
		"--refresh-package pytest", "--reinstall-package pytest", "--fork-strategy fewest",
		"--config-settings-package pytest:build.option=synthetic", "--exclude-newer 2026-01-01",
		"--no-build-isolation-package pytest", "--python-platform linux",
	} {
		for _, prefix := range []string{"", "env "} {
			for _, child := range []string{"python -V", "pytest", "cat README.md"} {
				source := prefix + "uv run " + options + " " + child
				if reason := Analyze(source, work, home, check); reason != "" {
					t.Errorf("public UV command %s: %s", source, reason)
				}
				if reason := AnalyzeArgv(strings.Fields(source), work, home, check); reason != "" {
					t.Errorf("public UV argv %s: %s", source, reason)
				}
			}
			for _, source := range []string{
				prefix + "uv run " + options + " --directory ~/.aws cat credentials",
				prefix + "uv run --directory ~/.aws " + options + " cat credentials",
			} {
				if reason := Analyze(source, work, home, check); reason == "" {
					t.Errorf("UV option hid reader cwd: %s", source)
				}
			}
		}
	}
	for _, source := range []string{"uv run -p", "uv run --only-group", "uv run --only-group test", "uv run --unsupported python -V"} {
		if reason := Analyze(source, work, home, check); reason == "" {
			t.Errorf("incomplete or unknown UV form allowed: %s", source)
		}
	}
}

func TestAudit27PipelineFilenameStdin(t *testing.T) {
	home, work, check := audit21Fixture(t)
	clean := filepath.Join(work, "sub")
	if err := os.WriteFile(filepath.Join(clean, "public.txt"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "external-names"), []byte(filepath.ToSlash(filepath.Join(home, ".aws", "credentials"))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source string
		deny   bool
	}{
		{`{ find . -name "*.txt" | xargs cat; } < external-names`, false},
		{`{ find . -name "*.txt" | env xargs cat; } < external-names`, false},
		{`{ find . -name "*.txt" | { xargs cat; }; } < external-names`, false},
		{`{ find . -name "*.txt" | xargs cat; } <<<'public.txt'`, false},
		{`{ find . -name "*.txt" | xargs cat; xargs cat; } < external-names`, true},
		{`{ find . -name "*.txt" | xargs cat < external-names; } < external-names`, true},
		{`find . -name "*.txt" | { xargs cat; } < external-names`, true},
		{`find . -name "*.txt" | { { xargs cat; }; } < external-names`, true},
		{`find . -name "*.txt" | xargs -a external-names cat`, true},
		{`{ find ~/.aws -type f | xargs cat; } < external-names`, true},
		{`{ find "$MISSING" -type f | xargs cat; } < external-names`, true},
		{`{ find ~/.aws -type f | env xargs cat; } < external-names`, true},
		{`{ xargs cat | cat; } < external-names`, true},
		{`{ find . -name "*.txt" | xargs cat && xargs cat; } < external-names`, true},
		{`{ find . -name "*.txt" | xargs cat; } < ~/.aws/credentials`, true},
	} {
		if reason := Analyze(tc.source, clean, home, check); (reason != "") != tc.deny {
			t.Errorf("%s: deny=%v reason=%q", tc.source, tc.deny, reason)
		}
	}
}

func TestAudit27DockerBindReaders(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, dir := range []string{filepath.Join(home, ".kube"), filepath.Join(work, "project")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".kube", "config"), filepath.Join(work, "project", "credentials"), filepath.Join(work, "project", "custom.cfg")} {
		if err := os.WriteFile(file, []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, source := range []string{
		"docker run --rm -v \"$HOME/.aws\":/input:ro alpine cat /input/credentials",
		"docker run -itv \"$HOME/.aws\":/input:ro alpine cat /input/credentials",
		"docker run -itv\"$HOME/.aws\":/input:ro -itw/input alpine cat credentials",
		"docker run -itv \"$HOME/.aws/credentials\":/input:ro alpine true",
		"docker run -itv \"$MISSING\":/input:ro alpine cat /input/credentials",
		"docker run -itv",
		"docker run -itw",
		"docker run --rm --volume=\"$HOME/.aws\":/input:ro alpine env cat /input/credentials",
		"docker run --rm -v\"$HOME/.aws\":/input:ro -w /input alpine cat credentials",
		"docker run --rm --mount type=bind,src=\"$HOME/.aws\",dst=/input,readonly alpine cat /input/credentials",
		"docker run --mount=type=bind,source=\"$HOME/.kube\",target=/input --workdir=/input alpine cat ./config",
		"docker --context synthetic run -v \"$HOME/.aws\":/input:ro alpine timeout 5 cat /input/nested/../credentials",
		"KUBECONFIG=project/custom.cfg; docker run -v ./project:/input:ro alpine cat /input/custom.cfg",
	} {
		for _, prefix := range []string{"", "env "} {
			if reason := Analyze(prefix+source, work, home, check); reason == "" {
				t.Errorf("bind reader allowed: %s", prefix+source)
			}
		}
	}
	aws := filepath.ToSlash(filepath.Join(home, ".aws"))
	for _, tc := range []struct {
		options []string
		operand string
	}{
		{[]string{"-itv", aws + ":/input:ro"}, "/input/credentials"},
		{[]string{"-itv" + aws + ":/input:ro"}, "/input/credentials"},
		{[]string{"-itv=" + aws + ":/input:ro"}, "/input/credentials"},
		{[]string{"-div", aws + ":/input:ro"}, "/input/credentials"},
		{[]string{"-itw", "/input", "-v", aws + ":/input:ro"}, "credentials"},
		{[]string{"-itw/input", "-v", aws + ":/input:ro"}, "credentials"},
		{[]string{"-v", aws + ":/input:ro", "-itw=/input"}, "./credentials"},
		{[]string{"-itv" + aws + ":/input:ro", "-itw/input"}, "credentials"},
		{[]string{"-ite", "MODE=synthetic", "-itv", aws + ":/input:ro"}, "/input/credentials"},
	} {
		for _, prefix := range [][]string{nil, {"env"}} {
			argv := append(append([]string{}, prefix...), "docker", "run")
			argv = append(argv, tc.options...)
			argv = append(argv, "alpine", "cat", tc.operand)
			if reason := AnalyzeArgv(argv, work, home, check); reason == "" {
				t.Errorf("clustered bind argv allowed: %q", argv)
			}
			quoted := make([]string, len(argv))
			for i, arg := range argv {
				quoted[i] = shellLiteral(arg)
			}
			if reason := Analyze(strings.Join(quoted, " "), work, home, check); reason == "" {
				t.Errorf("clustered bind shell allowed: %q", argv)
			}
		}
	}
	if reason := AnalyzeArgv([]string{"docker", "run", "-v", aws + ":/input:ro", "alpine", "cat", "/input/credentials"}, work, home, check); reason == "" {
		t.Fatal("literal argv bind reader allowed")
	}
	for _, source := range []string{
		"docker run --rm -v ./project:/input:ro alpine cat /input/credentials",
		"docker run --rm --mount type=bind,src=./project,dst=/input alpine cat /input/credentials",
		"docker run --rm -v \"$HOME/.aws\":/input:ro alpine stat /input/credentials",
		"docker run --rm -v \"$HOME/.aws\":/input:ro alpine cat /input-other/credentials",
		"docker run -v \"$HOME/.aws\":/input:ro -v ./project:/input:ro alpine cat /input/credentials",
		"docker run -v \"$HOME/.aws\":/input:ro -v ./project:/input/public:ro alpine cat /input/public/credentials",
		"docker run --env-file .env alpine true",
		"docker run -itv ./project:/input:ro -itw/input alpine cat credentials",
		"env docker run -itv./project:/input:ro -itw /input alpine cat credentials",
		"docker run -itv \"$HOME/.aws\":/input:ro alpine stat /input/credentials",
		"docker run -ite MODE=synthetic -itv ./project:/input:ro alpine cat /input/credentials",
		"docker run -v \"$PWD\":/src node:20 npm test",
		"docker run -itv\"$PWD\":/src node:20 npm test",
		"docker run -itv$(pwd):/src node:20 npm test",
		"docker run --rm -v ./project:/input:ro -w /input alpine cat ./credentials; cat credentials",
	} {
		if reason := Analyze(source, work, home, check); reason != "" {
			t.Errorf("safe bind control %s: %s", source, reason)
		}
	}
}
