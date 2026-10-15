package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

func TestRGConfigNativePathTrust(t *testing.T) {
	// Start with a physical cwd so the relative unchanged case does not
	// depend on Windows short-name aliases in the runner's temp directory.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{root, src} {
		if err := os.WriteFile(filepath.Join(dir, "prod.secret"), []byte("synthetic\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile("../../../examples/ripgreprc")
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "rg-options")
	// Both directories have a complete config, so a relative-path denial
	// must come from the cwd trust boundary, not a missing config file.
	for _, dir := range []string{root, src} {
		if err := os.WriteFile(filepath.Join(dir, "rg-options"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(name, cwd string) bool { return paths.Protected(name, cwd, "", root) }
	const command = "rg --iglob '{!*.md,!*.txt}' K"
	type testCase struct {
		name, config, cwd, source string
		deny                      bool
	}
	cases := []testCase{
		{"native absolute", config, root, command, false},
		{"normalized cwd", config, root + string(os.PathSeparator) + ".", command, false},
		{"changed cwd", config, root, "cd src && " + command, false},
		{"slash absolute", filepath.ToSlash(config), root, "cd src && " + command, false},
		{"relative unchanged cwd", "rg-options", root, command, false},
		{"relative changed cwd", "rg-options", root, "cd src && " + command, true},
		{"nested wrapper", config, root, "bash -c \"" + command + "\"", true},
		{"inline override", config, root, "RIPGREP_CONFIG_PATH=rg-options " + command, true},
	}
	if runtime.GOOS == "windows" {
		volume := filepath.VolumeName(config)
		cases = append(cases,
			testCase{"drive relative", volume + strings.TrimLeft(strings.TrimPrefix(config, volume), `\`), root, "cd src && " + command, true},
			testCase{"rooted without volume", strings.TrimPrefix(config, volume), root, "cd src && " + command, true},
		)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RIPGREP_CONFIG_PATH", tc.config)
			if got := Analyze(tc.source, tc.cwd, root, check); (got != "") != tc.deny {
				t.Errorf("denial=%q want deny=%v", got, tc.deny)
			}
		})
	}
}
