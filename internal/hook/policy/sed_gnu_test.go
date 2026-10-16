package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/avhn/secret/internal/hook/paths"
)

// TestSedGNUGrammar pins execution surfaces against GNU sed with disposable files.
func TestSedGNUGrammar(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNU sed evidence runs on Linux")
	}
	version, err := syntheticCommand(t, "sed", "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "GNU sed") {
		t.Skip("GNU sed unavailable")
	}
	cases := []struct {
		name, scriptFile string
		args             []string
		marker, probe    bool
	}{
		{"colon semicolon separates commands", "", []string{"-n", ":label;r @MARK@"}, true, false},
		{"branch label ends at semicolon", "", []string{"-n", "b label;r @MARK@\n:label\nr @MARK@"}, true, false},
		{"test label falls through without substitution", "", []string{"-n", "t label;r @MARK@\n:label"}, true, false},
		{"test label ends at semicolon", "", []string{"-n", "s/x/x/;t label;r @MARK@\n:label\nr @MARK@"}, true, false},
		{"inverse test label ends at semicolon", "", []string{"-n", "T label;r @MARK@\n:label\nr @MARK@"}, true, false},
		{"label ends at newline", "", []string{"-n", ":label;r @MARK@\nr @MARK@"}, true, false},
		{"one-line append", "", []string{"-n", "a text; r @MARK@"}, false, false},
		{"one-line insert", "", []string{"-n", "i text; r @MARK@"}, false, false},
		{"one-line change", "", []string{"-n", "c text; r @MARK@"}, false, false},
		{"classic append", "", []string{"-n", "a\\\ntext\nr @MARK@"}, true, false},
		{"classic insert", "", []string{"-n", "i\\\ntext\nr @MARK@"}, true, false},
		{"classic change", "", []string{"-n", "2c\\\ntext\nr @MARK@"}, true, false},
		{"continued append across expressions", "", []string{"-n", "-e", "a\\", "-e", "r @MARK@"}, false, false},
		{"continued insert across expressions", "", []string{"-n", "-e", "i\\", "-e", "r @MARK@"}, false, false},
		{"continued change across expressions", "", []string{"-n", "-e", "c\\", "-e", "r @MARK@"}, false, false},
		{"append ends across expressions", "", []string{"-n", "-e", "a text", "-e", "r @MARK@"}, true, false},
		{"insert ends across expressions", "", []string{"-n", "-e", "i text", "-e", "r @MARK@"}, true, false},
		{"change ends across expressions", "", []string{"-n", "-e", "2c text", "-e", "r @MARK@"}, true, false},
		{"bracket substitution delimiter", "", []string{"-n", "s[x[y[w @PROBE@"}, false, true},
		{"bracket transliteration delimiter", "", []string{"-n", "y[x[y[\nw @PROBE@"}, false, true},
		{"newline substitution delimiter", "", []string{"-n", "s\nx\ny\nw @PROBE@"}, false, false},
		{"newline transliteration delimiter", "", []string{"-n", "y\nx\ny\nw @PROBE@"}, false, false},
		{"first script separate", "", []string{"-ns", "r @MARK@"}, true, false},
		{"first script posix", "", []string{"-n", "--posix", "r @MARK@"}, true, false},
		{"first script debug", "", []string{"-n", "--debug", "r @MARK@"}, true, false},
		{"first script null data", "", []string{"-nz", "r @MARK@"}, true, false},
		{"first script extended regex", "", []string{"-nE", "r @MARK@"}, true, false},
		{"sandbox refuses read", "", []string{"-n", "--sandbox", "r @MARK@"}, false, false},
		{"sandbox refuses write", "", []string{"-n", "--sandbox", "w @PROBE@"}, false, false},
		{"sandbox refuses execute", "", []string{"-n", "--sandbox", "e cat @MARK@"}, false, false},
		{"uppercase read", "", []string{"-n", "R @MARK@"}, true, false},
		{"uppercase write", "", []string{"-n", "W @PROBE@"}, false, true},
		{"substitution write", "", []string{"-n", "s|x|y|w @PROBE@"}, false, true},
		{"execute", "", []string{"-n", "e cat @MARK@"}, true, false},
		{"substitution execute", "", []string{"-n", "s|x|cat @MARK@|ep"}, true, false},
		{"script file read", "r @MARK@", []string{"-n", "-f", "@SCRIPT@"}, true, false},
		{"script file write", "w @PROBE@", []string{"-n", "-f", "@SCRIPT@"}, false, true},
		{"script file execution", "e cat @MARK@", []string{"-n", "-f", "@SCRIPT@"}, true, false},
		{"script stdin dash", "r @MARK@", []string{"-n", "-f", "-"}, true, false},
		{"script stdin device", "r @MARK@", []string{"-n", "-f", "/dev/stdin"}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, ".env")
			probe := filepath.Join(root, ".secrets", "probe")
			if err := os.Mkdir(filepath.Dir(probe), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(marker, []byte("SYNTHETIC MARKER\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "in.txt"), []byte("x\n"), 0600); err != nil {
				t.Fatal(err)
			}
			replace := strings.NewReplacer("@MARK@", marker, "@PROBE@", probe, "@SCRIPT@", filepath.Join(root, "script.sed"))
			fileText := replace.Replace(tc.scriptFile)
			if tc.scriptFile != "" {
				if err := os.WriteFile(filepath.Join(root, "script.sed"), []byte(fileText+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := make([]string, 0, len(tc.args)+1)
			for _, arg := range tc.args {
				args = append(args, replace.Replace(arg))
			}
			cmd := syntheticCommand(t, "sed", append(args, "in.txt")...)
			cmd.Dir = root
			if strings.Contains(tc.name, "stdin") {
				cmd.Stdin = strings.NewReader(fileText + "\n")
			}
			output, _ := cmd.CombinedOutput()
			_, err := os.Stat(probe)
			created := err == nil
			appeared := strings.Contains(string(output), "SYNTHETIC MARKER")
			if appeared != tc.marker || created != tc.probe {
				t.Fatalf("GNU sed effect marker=%t probe=%t, want marker=%t probe=%t", appeared, created, tc.marker, tc.probe)
			}
			check := func(name, dir string) bool { return paths.Protected(name, dir, "", root) }
			if (appeared || created) && AnalyzeArgv(append([]string{"sed"}, append(args, "in.txt")...), root, root, check) == "" {
				t.Fatal("GNU sed performed a protected operation that the parser allowed")
			}
		})
	}
}
