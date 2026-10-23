package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDockerBindPath(t *testing.T) {
	binds := []dockerBind{
		{"/synthetic/alias/..", "/input"},
		{"/synthetic/old", "/input/public"},
		{"/synthetic/public", "/input/public"},
	}
	for _, tc := range []struct {
		operand, want string
	}{
		{"/input/credentials", "/synthetic/alias/../credentials"},
		{"/input/inner/../credentials", "/synthetic/alias/../inner/../credentials"},
		{"/input/public/credentials", "/synthetic/public/credentials"},
		{"/input/public/inner/../credentials", "/synthetic/public/inner/../credentials"},
		{"/input-other/credentials", ""},
		{"/input/../credentials", ""},
		{"/input/inner/../../credentials", ""},
		{"/input/public/../credentials", ""},
		{"/input/inner/../public/credentials", ""},
	} {
		got, ok := dockerBindPath(tc.operand, binds)
		got = filepath.ToSlash(got)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%q: path=%q mapped=%v want=%q", tc.operand, got, ok, tc.want)
		}
	}
}

// Candidate commands are analyzed only, with disposable symlinks and HOME.
func TestDockerBindPhysicalParents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs Windows developer mode")
	}
	home, work, check := audit21Fixture(t)
	for _, dir := range []string{filepath.Join(home, ".aws", "inner"), filepath.Join(work, "public", "inner"), filepath.Join(work, "nested")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{"alias", filepath.Join(home, ".aws", "inner")},
		{"nested/alias", filepath.Join(home, ".aws", "inner")},
		{"public-alias", filepath.Join(work, "public", "inner")},
	} {
		if err := os.Symlink(link.target, filepath.Join(work, filepath.FromSlash(link.name))); err != nil {
			t.Fatal(err)
		}
	}
	for _, engine := range []string{"docker", "podman"} {
		for _, tc := range []struct {
			name, source, operand string
			deny                  bool
		}{
			{"source_parent", "./alias/..", "/input/credentials", true},
			{"source_absolute", filepath.ToSlash(work) + "/alias/..", "/input/credentials", true},
			{"source_intermediate", "./nested/alias/..", "/input/credentials", true},
			{"source_missing", "./alias/..", "/input/config", true},
			{"source_dot_parent", "./alias/../inner/..", "/input/credentials", true},
			{"operand_parent", "./", "/input/alias/../credentials", true},
			{"operand_dots", "./", "/./input//./alias/../credentials", true},
			{"operand_intermediate", "./", "/input/nested/alias/../credentials", true},
			{"operand_missing", "./", "/input/alias/../config", true},
			{"operand_workdir", "./", "alias/../credentials", true},
			{"public_source", "./public-alias/..", "/input/credentials", false},
			{"public_operand", "./", "/input/public-alias/../credentials", false},
			{"public_workdir", "./", "public-alias/../credentials", false},
			{"public_basename", "./", "/input/credentials", false},
			{"public_outside", "./alias/..", "/input-other/credentials", false},
		} {
			for _, mount := range [][]string{
				{"-v", tc.source + ":/input:ro"},
				{"-itv" + tc.source + ":/input:ro"},
				{"--volume=" + tc.source + ":/input:ro"},
				{"--mount", "type=bind,source=" + tc.source + ",target=/input,readonly"},
				{"--mount=type=bind,src=" + tc.source + ",dst=/input"},
			} {
				t.Run(engine+"/"+tc.name+"/"+mount[0], func(t *testing.T) {
					argv := append([]string{engine, "run", "--workdir=/input"}, mount...)
					argv = append(argv, "alpine", "cat", tc.operand)
					if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != tc.deny {
						t.Errorf("argv %q: deny=%v reason=%q", argv, tc.deny, reason)
					}
					quoted := make([]string, len(argv))
					for i, arg := range argv {
						quoted[i] = shellLiteral(arg)
					}
					if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != tc.deny {
						t.Errorf("shell %q: deny=%v reason=%q", argv, tc.deny, reason)
					}
				})
			}
		}
		for _, tc := range []struct {
			source string
			deny   bool
		}{
			{work + "/alias/../credentials", true},
			{work + "/nested/alias/../config", true},
			{work + "/public-alias/../credentials", false},
		} {
			for _, source := range []string{tc.source, "synthetic:" + tc.source} {
				argv := []string{engine, "cp", source, "-"}
				if reason := AnalyzeArgv(argv, work, home, check); (reason != "") != tc.deny {
					t.Errorf("copy %q: deny=%v reason=%q", argv, tc.deny, reason)
				}
				quoted := make([]string, len(argv))
				for i, arg := range argv {
					quoted[i] = shellLiteral(arg)
				}
				if reason := Analyze(strings.Join(quoted, " "), work, home, check); (reason != "") != tc.deny {
					t.Errorf("copy shell %q: deny=%v reason=%q", argv, tc.deny, reason)
				}
			}
		}
	}
}
