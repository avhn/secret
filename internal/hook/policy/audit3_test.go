package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func audit3Fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"r/.secrets", "r3/.secrets", "cr/sub", "ar", "proj/.secrets", "proj/sub", "dirty", "clean"} {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(dir)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"r/app.env", "r/.secrets/store", "r/a.ts", "r/safe.txt", "r3/app.env", "r3/a.ts", "cr/a.ts", "proj/.secrets/store", "dirty/app.env", "ar/x.tar", "ar/x.zip", "clean/a.ts"} {
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"r", "r3"} {
		syntheticRepo(t, filepath.Join(root, dir), 2, ".secrets/store", "a.ts", "app.env", "safe.txt")
	}
	syntheticRepo(t, filepath.Join(root, "cr"), 4, "a.ts")
	for _, link := range []string{"proj/sub/link", "cr/sub/link"} {
		if err := os.Symlink(filepath.Join(root, "proj", ".secrets", "store"), filepath.Join(root, filepath.FromSlash(link))); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestAudit3Reproducers(t *testing.T) {
	skipUnixCWD(t) // The retained reproductions contain Unix /proc and /dev paths.
	root := audit3Fixture(t)
	data, err := os.ReadFile("testdata/audit3.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name, CWD, Command string
		Deny               bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	denies, allows := 0, 0
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			command := strings.ReplaceAll(tc.Command, "@ROOT@", filepath.ToSlash(root))
			cwd := filepath.Join(root, tc.CWD)
			check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
			reason := Analyze(command, cwd, root, check)
			if (reason != "") != tc.Deny {
				t.Fatalf("deny=%v want %v for %q: %s", reason != "", tc.Deny, command, reason)
			}
			// The argv host route must retain the same nested-shell policy.
			reason = AnalyzeArgv([]string{"bash", "-c", command}, cwd, root, check)
			if (reason != "") != tc.Deny {
				t.Fatalf("argv deny=%v want %v: %s", reason != "", tc.Deny, reason)
			}
		})
		if tc.Deny {
			denies++
		} else {
			allows++
		}
	}
	t.Logf("%d audit3 commands: %d denials, %d allows, each through shell and argv", len(cases), denies, allows)
}

func TestGitPolicyV2SafeForms(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 3, ".env", "safe.go")
	if err := os.WriteFile(filepath.Join(root, "safe.go"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"git status", "git status --short", "git status .env", "git log --oneline", "git log --format=%B", "git log -n 2 --graph",
		"git diff --stat", "git diff --name-only", "git diff --numstat", "git diff --quiet", "git diff --exit-code",
		"git add safe.go", "git add -A", "git commit -m 'handle .env safely'", "git commit -F safe.go",
		"git branch --list", "git tag --list", "git remote -v", "git rev-parse HEAD", "git rev-list --count HEAD",
		"git ls-files", "git ls-tree --name-only HEAD", "git show-ref", "git symbolic-ref HEAD", "git merge-base HEAD HEAD~1", "git describe --tags",
		"git restore safe.go", "git checkout main", "git switch main", "git stash list", "git fetch --all", "git pull --ff-only", "git push --dry-run",
		"git clone https://example.invalid/repo destination", "git init", "git merge --no-edit main", "git rebase main", "git cherry-pick HEAD", "git revert --no-edit HEAD",
		"git reset --hard HEAD", "git rm safe.go", "git mv safe.go next.go", "git worktree list", "git gc", "git prune", "git blame safe.go",
		"git -c color.ui=always log --oneline", "git -ccolor.ui=always log --oneline",
		"git --namespace demo --attr-source HEAD status", "git config --get user.name",
	} {
		t.Run(command, func(t *testing.T) {
			if reason := Analyze(command, root, root, func(name, dir string) bool { return paths.Protected(name, dir, "", root) }); reason != "" {
				t.Fatalf("safe form denied: %s", reason)
			}
		})
	}
	ignored := t.TempDir()
	syntheticRepo(t, ignored, 4, "safe.go")
	for name, content := range map[string]string{".env": "SYNTHETIC=fixture\n", ".gitignore": ".env\n", "safe.go": ""} {
		if err := os.WriteFile(filepath.Join(ignored, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{"git log -p", "git diff", "git show HEAD"} {
		t.Run("ignored untracked/"+command, func(t *testing.T) {
			if reason := Analyze(command, ignored, ignored, func(name, dir string) bool { return paths.Protected(name, dir, "", ignored) }); reason != "" {
				t.Fatalf("ignored untracked file influenced index gate: %s", reason)
			}
		})
	}
}

func TestPolicyV2FailurePaths(t *testing.T) {
	root := t.TempDir()
	syntheticRepo(t, root, 2, ".env", "safe.go")
	if err := os.WriteFile(filepath.Join(root, ".env"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	if reason := Analyze("xargs -a safe.go cat", root, root, check); reason != "" {
		t.Fatalf("safe explicit xargs arg-file denied: %s", reason)
	}
	for _, command := range []string{
		"git --unknown status", "git --namespace", "git -c", "git --config-env=core.editor=MISSING status",
		"git -c alias.a=a a", "git -c alias.a='-c core.editor=printenv commit' a", "git -c alias.a='$UNKNOWN' a",
		"git -c core.editor='$UNKNOWN' status", "git -c core.editor='echo .env' status", "git -c core.editor='echo safe' status", "git -c include.path=safe status", "git -c core.hooksPath=safe status",
		"GIT_CONFIG_COUNT=129 git status", "GIT_CONFIG_COUNT=1 git status", "GIT_CONFIG_COUNT=no git status",
		"GIT_DIR=$UNKNOWN git log -p", "GIT_INDEX_FILE=other git log -p",
		"git log --unknown-output", "git status -v", "git rev-list --objects HEAD", "git log -p -- safe.go",
		"git log --full-diff -- safe.go", "git config --get http.extraheader", "git config --get remote.origin.url", "git config --get-regexp .*", "git blame --contents=safe.go safe.go", "git config --get credential.helper", "git config --list",
		"tar --unknown x.tar", "tar --cre --file=out.tar .", "tar -xf archive.tar --to-command=cat",
		"bsdtar -xOf archive.tar", "unzip -pC archive.zip '*.env'", "cpio -i --to-stdout", "7z e -so archive.zip",
		"jq -fn .env", "jq -nf .env", "jq -f -n .env", "jq -n -f .env", "jq --from-file -n .env",
		"jq --unknown .", "jq -f", "parallel --unknown cat", "xargs --unknown cat", "xargs -- cat -a",
		"dirs; cat relative", "pushd safe; cat relative", "popd; cat relative", "cd ~-; cat relative", "cd ~+; cat relative", "cd ~1; cat relative",
		"shopt -s autocd; cat relative", "shopt -s cdable_vars; cat relative",
	} {
		t.Run(command, func(t *testing.T) {
			if Analyze(command, root, root, check) == "" {
				t.Fatal("indeterminate or protected form allowed")
			}
		})
	}
}

func TestMetadataChildren(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, child := range strings.Fields("ls stat chmod chown rm rmdir touch mkdir test true false basename dirname realpath readlink file") {
		for _, command := range []string{"find . -exec " + child + " {} +", "find . -exec env timeout 1 " + child + " {} +", "xargs " + child, "parallel " + child} {
			t.Run(command, func(t *testing.T) {
				if reason := Analyze(command, root, root, check); reason != "" {
					t.Fatalf("metadata child denied: %s", reason)
				}
			})
		}
	}
	for _, child := range []string{"unmodeled-reader", "env timeout 1 cp", "nice dd", "stdbuf -oL fold", "split", "sh -c 'echo safe'"} {
		for _, command := range []string{"find . -exec " + child + " {} +", "xargs " + child, "parallel " + child} {
			t.Run(command, func(t *testing.T) {
				if Analyze(command, root, root, check) == "" {
					t.Fatal("non-metadata child allowed in protected scope")
				}
			})
		}
	}
}

func TestScriptAndProcessRoles(t *testing.T) {
	skipUnixCWD(t)
	root := t.TempDir()
	for _, file := range []string{"app.env", "safe.txt"} {
		if err := os.WriteFile(filepath.Join(root, file), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("app.env", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
	for _, command := range []string{
		"GIT_EDITOR=./link git status", "git -c core.editor='./link --flag' status", "git mergetool -c'cat link'",
		"sed -n 'r link' safe.txt", "sed -n '1R link' safe.txt", "sed -n '/x/r link' safe.txt",
		"sed -n '\\@x@r link' safe.txt", "sed -n '1 {\nr link\n}' safe.txt",
		"sed -nerlink safe.txt", "sed --expression='r link' safe.txt", "sed --expr='r link' safe.txt",
		"sed -n 'w link' safe.txt", "sed -n 'W link' safe.txt", "sed -n 'e cat link' safe.txt", "sed -n 'ecat link' safe.txt",
		"sed -n '/x/e cat link' safe.txt", "sed -n 's|x|cat link|e' safe.txt",
		`awk 'BEGIN { getline x < "link"; print x }'`, `awk 'BEGIN { print "safe" > "link" }'`, `awk 'BEGIN { system("cat link") }'`,
		"cat /proc/self/task/1/cwd/file", "cat /proc/123/fd/4", "cat /proc/*/task/*/cwd/file", "cat /proc/self/mem",
		"cat /dev/stdin/file", "cat /dev/stdout/file", "cat /dev/stderr/file", "cat /dev/fd/3", "cat /proc/self/fd/3 3<app.env",
	} {
		t.Run(command, func(t *testing.T) {
			if Analyze(command, root, root, check) == "" {
				t.Fatal("protected script or dynamic process operand allowed")
			}
		})
	}
	for _, command := range []string{
		"sed -n '1,20p' safe.txt", "sed -e 's/foo/bar/' safe.txt", "sed -f safe.txt safe.txt", `awk '{print $1}' safe.txt`,
		"cat /proc/cpuinfo", "cat /proc/meminfo", "cat /proc/loadavg", "cat /proc/uptime", "cat /proc/version", "cat /proc/stat", "cat /proc/self/status",
		"tar -tf archive.tar .env", "unzip -l archive.zip '*.env'", "unzip -Z archive.zip", "7z l archive.zip", "cpio -t",
	} {
		t.Run(command, func(t *testing.T) {
			if reason := Analyze(command, root, root, check); reason != "" {
				t.Fatalf("safe role denied: %s", reason)
			}
		})
	}
}
