package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

func TestAudit25PerlQuoteBoundaries(t *testing.T) {
	for _, code := range []string{`q{public`, `qq[public`, `qw(public`, `qx<public`, `q#public`, `q{public\}`} {
		tokens := interpreterTokens(code, "perl")
		if len(tokens) != 1 || !tokens[0].indeterminate || tokens[0].literal || tokens[0].witness {
			t.Errorf("unterminated %s: %#v", code, tokens)
		}
	}
	for _, code := range []string{`q=>1`, `qq => 1`, `$h{q}`, `$h{ q }`, `$o->q`, `$o -> q`} {
		tokens := interpreterTokens(code+`; system("dotenvx","get")`, "perl")
		found := false
		for _, token := range tokens {
			if token.indeterminate {
				t.Errorf("key consumed later source %s: %#v", code, tokens)
			}
			found = found || token.text == "system"
		}
		if !found {
			t.Errorf("key hid later launch %s: %#v", code, tokens)
		}
	}
	for _, code := range []string{`q{public}`, `qq[public]`, `qw(public)`, `qx<date>`, `q#public#`} {
		tokens := interpreterTokens(code, "perl")
		if len(tokens) != 1 || !tokens[0].literal || tokens[0].indeterminate {
			t.Errorf("complete %s: %#v", code, tokens)
		}
	}
}

func TestAudit25LuaLongStrings(t *testing.T) {
	for _, tc := range []struct{ code, value string }{
		{`[[hi]]`, "hi"}, {`[=[a [[b]] c]=]`, "a [[b]] c"},
		{`[==[a ]=] b]==]`, "a ]=] b"}, {`[[a\b]]`, `a\b`},
	} {
		for _, program := range []string{"lua", "lua5.4", "luajit"} {
			tokens := interpreterTokens(tc.code, program)
			if len(tokens) != 1 || !tokens[0].literal || !tokens[0].witness || tokens[0].text != tc.value {
				t.Errorf("%s %s: %#v", program, tc.code, tokens)
			}
		}
	}
	for _, code := range []string{`[[public`, `[=[public]]`, `[==[public]=]`} {
		tokens := interpreterTokens(code, "lua")
		if len(tokens) != 1 || !tokens[0].indeterminate {
			t.Errorf("unterminated %s: %#v", code, tokens)
		}
	}
}

func TestAudit25CommentBoundaries(t *testing.T) {
	for _, code := range []string{`--[[public`, `--[==[public]=]`} {
		tokens := interpreterTokens(code, "lua")
		if len(tokens) != 1 || !tokens[0].indeterminate {
			t.Errorf("unterminated comment %s: %#v", code, tokens)
		}
	}
	for _, code := range []string{`--[[x]] marker`, `--[==[x]==] marker`, "-- plain\nmarker"} {
		tokens := interpreterTokens(code, "lua")
		if len(tokens) != 1 || tokens[0].text != "marker" || tokens[0].indeterminate {
			t.Errorf("comment hid following token %s: %#v", code, tokens)
		}
	}
	for _, code := range []string{"--", "-- public"} {
		if tokens := interpreterTokens(code, "lua"); len(tokens) != 0 {
			t.Errorf("plain comment %s: %#v", code, tokens)
		}
	}
	for _, code := range []string{"q # comment", "qq \t# comment", "qw \n# comment", "qx # comment"} {
		if _, _, ok := perlLiteralTokens(code, 0); ok {
			t.Errorf("whitespace-separated # became a quote delimiter: %s", code)
		}
	}
	for _, code := range []string{"q # comment\n{has#hash}", "q \t# first\n # second\n{has#hash}"} {
		tokens := interpreterTokens(code, "perl")
		if len(tokens) != 1 || !tokens[0].literal || tokens[0].text != "has#hash" {
			t.Errorf("comment-delayed delimiter lost literal boundaries %s: %#v", code, tokens)
		}
	}
	for _, program := range []string{"perl", "ruby"} {
		if tokens := interpreterTokens(`x = /grep -r TOKEN ./`, program); unextractedRecursiveGrep(tokens) {
			t.Errorf("inert regex became an unextracted witness: %#v", tokens)
		}
	}
}

func TestAudit25RegexInterpolation(t *testing.T) {
	for _, tc := range []struct{ program, code string }{
		{"ruby", `#{system("echo","public#safe")}`},
		{"perl", `@{[system(q{echo},q{public#safe})]}`},
	} {
		found := false
		for _, token := range interpreterBodyTokens(tc.code, tc.program, true) {
			found = found || token.literal && token.text == "public#safe"
		}
		if !found {
			t.Errorf("regex body changed literal bytes: %s", tc.code)
		}
	}
	for _, program := range []string{"ruby", "perl"} {
		for _, code := range []string{`x = /#{system("dotenvx","get")}/`, "p /#{`gh auth token`}/", `x = /@{[system(qw(dotenvx get))]}/`} {
			found := false
			for _, token := range interpreterTokens(code, program) {
				if token.regexCode {
					found = true
					if token.opaque {
						t.Errorf("interpolated regex became opaque: %#v", token)
					}
				}
			}
			if !found {
				t.Errorf("%s lost regex interpolation: %s", program, code)
			}
		}
		for _, token := range interpreterTokens(`x = /a+/`, program) {
			if token.regexCode {
				t.Errorf("plain regex became executable code: %#v", token)
			}
		}
	}
}

func TestAudit25RegexWorkBound(t *testing.T) {
	// Unclosed classes make successive slash candidates overlap. No language
	// source is run, and the input stays under the ordinary fragment limit.
	code := "p " + strings.Repeat("/[", 2048) + "$x"
	for _, program := range []string{"ruby", "perl", "node"} {
		indeterminate := false
		for _, token := range interpreterTokens(code, program) {
			indeterminate = indeterminate || token.indeterminate
		}
		if !indeterminate {
			t.Errorf("%s overlapping regex scans exceeded the work bound", program)
		}
	}
	for _, program := range []string{"ruby", "perl", "node"} {
		for _, token := range interpreterTokens(`x = /[a-z]+/`, program) {
			if token.indeterminate {
				t.Errorf("%s ordinary regex exhausted the work bound", program)
			}
		}
	}
}

func TestAudit25Argv(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		program, code string
		deny          bool
	}{
		{"ruby", `x = /grep -r TOKEN ./;`, true},
		{"perl", `my $x = /grep -r TOKEN ./;`, true},
		{"ruby", `p /#{system("dotenvx","get")}/`, true},
		{"perl", `my $x = /@{[system(qw(dotenvx get))]}/`, true},
		{"ruby", `p "a" =~ /a+/`, false},
		{"perl", `print "x" =~ /x/`, false},
		{"ruby", `p /#{system("echo","public")}/`, false},
		{"perl", `my $x = /@{[system(qw(echo public))]}/`, false},
		{"perl", "print `grep -r TOKEN .`", true},
		{"ruby", "puts `grep -r TOKEN .`", true},
		{"lua", `os.execute([[grep -r TOKEN .]])`, true},
		{"lua", `os.execute([==[grep -r TOKEN .]==])`, true},
		{"lua", `--[[x]] os.execute([[grep -r TOKEN .]])`, true},
		{"lua", `--[==[x]==] os.execute([[grep -r TOKEN .]])`, true},
		{"lua", `--[[public`, true},
		{"lua", `--[[x]] print([[hi]])`, false},
		{"lua", `-- public`, false},
		{"perl", "my $x=q # comment\n{public}; system(\"dotenvx\",\"get\"); # closing hash #", true},
		{"perl", "my $x=q # comment\n{public}; print 1; # closing hash #", false},
		{"ruby", `%x[grep -r TOKEN .]`, true},
		{"perl", `q{public`, true},
		{"perl", `my %h=(q=>1); system("dotenvx","get")`, true},
		{"perl", `print $h{q}; system("dotenvx","get")`, true},
		{"perl", `$o->q; system("dotenvx","get")`, true},
		{"perl", `my %h=(q=>1); print $h{q}`, false},
		{"lua", `print([[hi]])`, false},
		{"ruby", "puts `date`", false},
		{"perl", "print `grep -rc TOKEN .`", false},
		{"ruby", "puts `grep -rl TOKEN .`", false},
		{"lua", `os.execute([[grep -rq TOKEN .]])`, false},
	} {
		if reason := AnalyzeArgv([]string{tc.program, "-e", tc.code}, work, home, check); (reason != "") != tc.deny {
			t.Errorf("%s %s: reason=%q want deny=%v", tc.program, tc.code, reason, tc.deny)
		}
	}
}

// Check the local producer invariant independently of Analyze's final uncertainty
// check. Unknown input must not depend on that later check to remain denied.
func TestAudit25IndeterminateProducer(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, source := range []string{
		`printf '%s\n' "${unknown}"'system("dotenvx","get")'`,
		`printf '%s\n' 'system("dotenvx","get")'{1..2}`,
		`cat <<< "${unknown}"`,
	} {
		file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
		if err != nil {
			t.Fatal(err)
		}
		a := &analyzer{protected: check, cwd: work, home: home, source: source, deadline: time.Now().Add(2 * time.Second)}
		if !a.interpreterProducer(file.Stmts[0], work, work, "perl") || a.reason != roles.Indeterminate {
			t.Errorf("%s: reason=%q", source, a.reason)
		}
		if reason := Analyze(source+" | perl", work, home, check); reason == "" {
			t.Errorf("unknown executable stdin allowed: %s", source)
		}
	}
}
