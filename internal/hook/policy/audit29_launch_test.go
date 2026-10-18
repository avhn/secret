package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Launch sources are analyzer inputs only. All metadata uses a disposable HOME.
func TestAudit29LaunchDenoComputedArgs(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, key := range []string{"[`args`]", `["args"]`, "['args']", "args", `"args"`} {
		for _, layout := range []string{"%s:[%s]", "...options,%s:[%s]", "%s:[%s],...other", "...options,%s:[%s],...other"} {
			for _, child := range []struct {
				name, args string
				deny       bool
			}{
				{"gh", `"auth","token"`, true}, {"env", `"gh","auth","token"`, true},
				{"cat", `"README.md"`, false}, {"echo", `"public"`, false},
			} {
				code := fmt.Sprintf("new Deno.Command(%q,{%s}).outputSync()", child.name, fmt.Sprintf(layout, key, child.args))
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

func TestAudit29LaunchDenoConstructorBoundaries(t *testing.T) {
	for _, tc := range []struct {
		options string
		known   bool
	}{
		{"[`args`]:['auth','token']", true},
		{"...options,[`args`]:['auth','token'],...other", true},
		{"[`args`]:['auth','token'],[dynamic]:value", true},
		{"[dynamic]:['auth','token']", false},
		{"[`arg${suffix}`]:['auth','token']", false},
		{"['arg'+'s']:['auth','token']", false},
		{"other:{[`args`]:['auth','token']}", false},
		{"[`args`]:['auth',token]", false},
	} {
		tokens := interpreterTokens("'gh',{"+tc.options+"})", "deno")
		launches := constructorArguments(tokens, 0)
		if (len(launches) > 0) != tc.known {
			t.Errorf("%s: launches=%q, want known=%v", tc.options, launches, tc.known)
		}
		if tc.known && (len(launches) != 1 || strings.Join(launches[0], "|") != "gh|auth|token") {
			t.Errorf("%s: wrong argv witness %q", tc.options, launches)
		}
	}
}

func TestAudit29LaunchDenoChildCwd(t *testing.T) {
	home, work, check := audit21Fixture(t)
	aws := filepath.ToSlash(filepath.Join(home, ".aws"))
	if err := os.WriteFile(filepath.Join(home, ".aws", "public.txt"), []byte("synthetic\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, layout := range []string{
		"args:['%s'],cwd:'%s'", "cwd:'%[2]s',args:['%[1]s']",
		"[`args`]:['%s'],[`cwd`]:'%s'", "['cwd']:'%[2]s',['args']:['%[1]s']",
		"...options,args:['%s'],cwd:'%s',...other",
		"args:['%s'],cwd:'%s',cwd:'.'",
	} {
		for _, target := range []string{"credentials", "public.txt"} {
			code := "await new Deno.Command('cat',{" + fmt.Sprintf(layout, target, aws) + "}).spawn().status;"
			deny := target == "credentials"
			for _, source := range []string{
				"deno eval " + shellLiteral(code),
				"deno run --allow-run - <<< " + shellLiteral(code),
				"deno run --allow-run - <<'CODE'\n" + code + "\nCODE",
				"printf '%s\\n' " + shellLiteral(code) + " | deno run --allow-run -",
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != deny {
					t.Errorf("%s: deny=%v reason=%q", source, deny, reason)
				}
			}
			if reason := AnalyzeArgv([]string{"deno", "eval", code}, work, home, check); (reason != "") != deny {
				t.Errorf("argv %s: deny=%v reason=%q", code, deny, reason)
			}
		}
	}
	for _, options := range []string{
		"args:['credentials'],cwd:unknown",
	} {
		code := "new Deno.Command('cat',{" + options + "}).outputSync()"
		if reason := AnalyzeArgv([]string{"deno", "eval", code}, work, home, check); reason == "" {
			t.Errorf("uncertifiable child cwd allowed: %s", code)
		}
	}
	for _, options := range []string{
		"args:['credentials'],other:{cwd:'" + aws + "'}",
		"args:['credentials'],cwd:null", "args:['credentials'],cwd:''",
	} {
		code := "new Deno.Command('cat',{" + options + "}).outputSync()"
		if reason := AnalyzeArgv([]string{"deno", "eval", code}, work, home, check); reason != "" {
			t.Errorf("unrelated/default cwd changed child: %s: %s", code, reason)
		}
	}
	code := "new Deno.Command('true',{args:[],cwd:'" + aws + "'}).outputSync()"
	if reason := Analyze("deno eval "+shellLiteral(code)+"; cat credentials", work, home, check); reason != "" {
		t.Errorf("constructor cwd escaped child scope: %s", reason)
	}
}

func TestAudit29LaunchPackageExecutable(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"./tools@v1/printenv", "./tools@v1/printenv"},
		{"tools@v1/printenv", "tools@v1/printenv"},
		{"/synthetic/tools@v1/printenv", "/synthetic/tools@v1/printenv"},
		{`C:\synthetic\tools@v1\printenv`, `C:\synthetic\tools@v1\printenv`},
		{"./tools/printenv@v1", "./tools/printenv@v1"},
		{"@scope/tools@v1/printenv", "@scope/tools@v1/printenv"},
		{"printenv@latest", "printenv"}, {"gh@1.2.3", "gh"},
		{"gh@https://synthetic.invalid/package", "gh"},
		{"@scope/gh@https://synthetic.invalid/package", "@scope/gh"},
		{"@scope/package", "@scope/package"}, {"@scope/package@latest", "@scope/package"},
		{"@dotenvx/dotenvx@latest", "dotenvx"}, {"@dotenvx/dotenvx", "dotenvx"},
		{"python-dotenv@latest", "dotenv"}, {"python-dotenv", "dotenv"},
		{"cat", "cat"}, {"true", "true"},
	} {
		if got := packageChildExecutable(tc.input); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.input, got, tc.want)
		}
		for _, launcher := range [][]string{{"pnpm", "exec"}, {"npm", "exec", "--"}, {"npx"}, {"bunx"}, {"uvx"}} {
			args := append(append([]string{}, launcher[1:]...), tc.input, "argument")
			child, ok := safePackageChild(launcher[0], args)
			if !ok || len(child) != 2 || child[0] != tc.want || child[1] != "argument" {
				t.Errorf("%q %q: got %q, ok=%v; want [%q argument]", launcher[0], args, child, ok, tc.want)
				continue
			}
			child[0] = "mutated"
			if args[len(args)-2] != tc.input {
				t.Errorf("%q mutated caller argv: %q", launcher[0], args)
			}
		}
	}
}

func TestAudit29LaunchPackageAtPaths(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, launcher := range [][]string{{"pnpm", "exec"}, {"npm", "exec", "--"}, {"npx"}, {"bunx"}, {"uvx"}} {
		for _, prefix := range []string{"./tools@v1/", "tools@v1/", filepath.ToSlash(filepath.Join(work, "tools@v1")) + "/"} {
			for _, child := range []struct {
				name string
				args []string
				deny bool
			}{
				{"printenv", nil, true}, {"cat", []string{filepath.ToSlash(filepath.Join(home, ".aws", "credentials"))}, true},
				{"cat", []string{"README.md"}, false}, {"true", nil, false},
			} {
				argv := append(append([]string{}, launcher...), prefix+child.name)
				argv = append(argv, child.args...)
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
}
