package policy

import (
	"reflect"
	"strings"
	"testing"
)

// Source is tokenized only, never executed. Every interpreter uses the shared
// member normalizer, including stdin and decoded executable-option values.
func TestAudit26MemberTokens(t *testing.T) {
	for _, name := range []string{"python3", "pypy3", "ruby", "perl", "node", "nodejs", "bun", "deno", "lua5.4", "luajit", "php", "rscript", "awk", "gawk", "jq", "yq"} {
		for _, code := range []string{"Deno.Command", "Deno. Command", "Deno.\nCommand", "Deno.\t\r\n Command", "Deno . Command", "Deno \n.\n Command"} {
			tokens := interpreterTokens(code+`("gh")`, name)
			if len(tokens) != 4 || tokens[0].text != "Deno.Command" || !tokens[2].literal || tokens[2].text != "gh" {
				t.Errorf("%s %q: %#v", name, code, tokens)
			}
		}
		for _, code := range []string{`"Deno. Command"`, `"Deno.\nCommand"`} {
			tokens := interpreterTokens(code, name)
			if len(tokens) != 1 || !tokens[0].witness {
				t.Errorf("quoted %s %q: %#v", name, code, tokens)
			}
		}
	}
	for _, name := range []string{"ruby", "perl"} {
		tokens := interpreterTokens("first\nsecond", name)
		if len(tokens) != 3 || tokens[1].text != "\n" {
			t.Errorf("%s statement newline lost: %#v", name, tokens)
		}
	}
	for _, code := range []string{`Deno."Command"`, `"Deno".Command`, `Deno./Command/`, "Deno. `Command`"} {
		for _, token := range interpreterTokens(code, "deno") {
			if token.text == "Deno.Command" {
				t.Errorf("data became a member: %s", code)
			}
		}
	}
}

func TestAudit26NumericBudget(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, name := range []string{"ruby", "node"} {
		for _, deny := range []bool{false, true} {
			code := strings.Repeat("1. 2; ", 128)
			if deny {
				code += "1"
			}
			if reason := AnalyzeArgv([]string{name, "-e", code}, work, home, check); (reason != "") != deny {
				t.Errorf("%s numeric budget deny=%v: %q", name, deny, reason)
			}
			if reason := Analyze(name+" -e "+shellLiteral(code), work, home, check); (reason != "") != deny {
				t.Errorf("shell %s numeric budget deny=%v: %q", name, deny, reason)
			}
		}
	}
}

func TestAudit26CodeOptions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args, want []string
	}{
		{"ruby", []string{"-esystem(1)"}, []string{"-e", "system(1)"}},
		{"ruby", []string{"-W0nesystem(1)"}, []string{"-W0ne", "system(1)"}},
		{"ruby", []string{"-0esystem(1)"}, []string{"-0e", "system(1)"}},
		{"ruby", []string{"-0777nesystem(1)"}, []string{"-0777ne", "system(1)"}},
		{"ruby", []string{"-E", "UTF-8", "-esystem(1)"}, []string{"-E", "UTF-8", "-e", "system(1)"}},
		{"ruby", []string{"-EUTF-8", "-esystem(1)"}, []string{"-EUTF-8", "-e", "system(1)"}},
		{"ruby", []string{"-E", "-esystem(1)"}, nil},
		{"ruby", []string{"-Eesystem(1)"}, nil},
		{"perl", []string{"-0777wEexec(1)"}, []string{"-0777wE", "exec(1)"}},
		{"perl", []string{"-l0nesystem(1)"}, []string{"-l0ne", "system(1)"}},
		{"python3", []string{"-IBcprint(1)"}, []string{"-IBc", "print(1)"}},
		{"pypy3", []string{"-cprint(1)"}, []string{"-c", "print(1)"}},
		{"node", []string{"-pexecFile(1)"}, []string{"-p", "execFile(1)", "-pe", "xecFile(1)"}},
		{"nodejs", []string{"-ipespawn(1)"}, []string{"-ip", "espawn(1)", "-ipe", "spawn(1)"}},
		{"bun", []string{"--eval=Bun.spawn(1)"}, []string{"--eval", "Bun.spawn(1)"}},
		{"deno", []string{"--print=Deno.Command(1)"}, []string{"--print", "Deno.Command(1)"}},
		{"lua5.4", []string{"-eos.execute(1)"}, []string{"-e", "os.execute(1)"}},
		{"luajit", []string{"-eos.execute(1)"}, []string{"-e", "os.execute(1)"}},
		{"php", []string{"-nrproc_open(1)"}, []string{"-nr", "proc_open(1)"}},
		{"php", []string{"--run=proc_open(1)"}, []string{"--run", "proc_open(1)"}},
		{"rscript", []string{"-esystem(1)"}, []string{"-e", "system(1)"}},
		{"awk", []string{"-esystem(1)"}, []string{"-e", "system(1)"}},
		{"gawk", []string{"--source=system(1)"}, []string{"--source", "system(1)"}},
		{"ruby", []string{"-Iesystem(1)", "-i.esystem(1)", "-e", "system(1)"}, nil},
		{"perl", []string{"-Fesystem(1)", "-Mexec(1)", "-i.esystem(1)"}, nil},
		{"python3", []string{"-Wcprint(1)", "-Xcprint(1)", "--config=print(1)"}, nil},
		{"node", []string{"--env-file=public", "--require=exec(1)", "-rpeexec(1)"}, nil},
		{"node", []string{"--env-file", "-eexec(1)", "--require", "-pspawn(1)"}, nil},
		{"ruby", []string{"-I", "-esystem(1)", "-e", "-eexec(1)"}, nil},
		{"ruby", []string{"-I", "--", "-esystem(1)"}, []string{"-I", "--", "-e", "system(1)"}},
		{"perl", []string{"-F", "-esystem(1)", "-Eexec(1)"}, []string{"-F", "-e", "system(1)", "-E", "exec(1)"}},
		{"python3", []string{"-W", "-cprint(1)", "-cprint(2)"}, []string{"-W", "-cprint(1)", "-c", "print(2)"}},
		{"ruby", []string{"--", "-esystem(1)"}, nil},
		{"ruby", []string{"public.rb", "-esystem(1)"}, nil},
		{"node", []string{"public.js", "--eval=execFile(1)"}, nil},
		{"bun", []string{"run", "-eBun.spawn(1)"}, []string{"run", "-e", "Bun.spawn(1)"}},
		{"bun", []string{"run", "public.js", "-eBun.spawn(1)"}, nil},
		{"deno", []string{"eval", "--print=Deno.Command(1)"}, []string{"eval", "--print", "Deno.Command(1)"}},
		{"ruby", []string{"-eputs(1)", "--", "-esystem(1)"}, []string{"-e", "puts(1)", "--", "-esystem(1)"}},
		{"jq", []string{"--arg", "public", "-esystem(1)", "."}, nil},
		{"yq", []string{"-esystem(1)"}, nil},
	} {
		want := tc.want
		if want == nil {
			want = tc.args
		}
		original := append([]string(nil), tc.args...)
		if got := interpreterCodeArgs(tc.name, tc.args); !reflect.DeepEqual(got, want) {
			t.Errorf("%s %q: got %q want %q", tc.name, tc.args, got, want)
		}
		if !reflect.DeepEqual(tc.args, original) {
			t.Errorf("%s mutated input argv: %q", tc.name, tc.args)
		}
	}
}
