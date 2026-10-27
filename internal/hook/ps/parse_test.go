package ps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParserLimits(t *testing.T) {
	nested := func(n int) string {
		return strings.Repeat("Write-Output x | % { ", n) + "Write-Output y" + strings.Repeat(" }", n)
	}
	nodesAtCap := strings.Repeat("Out-Null;", 679) + "Write-Output x;Write-Output y"
	cases := []struct{ name, at, past string }{
		{"source", strings.Repeat(" ", MaxSource), strings.Repeat(" ", MaxSource+1)},
		{"tokens", strings.Repeat("#\n", MaxTokens/2), strings.Repeat("#\n", MaxTokens/2) + "#"},
		{"nodes", nodesAtCap, strings.Repeat("Out-Null;", 680) + "% { Out-Null }"},
		{"words", "Write-Output " + strings.Repeat("x ", MaxWords-1), "Write-Output " + strings.Repeat("x ", MaxWords)},
		{"redirect words", "Write-Output " + strings.Repeat("> x ", MaxWords-1), "Write-Output " + strings.Repeat("> x ", MaxWords)},
		{"depth", nested(MaxDepth), nested(MaxDepth + 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.at), context.Background()); err != nil {
				t.Fatalf("at cap: %v", err)
			}
			tree, err := Parse([]byte(tc.past), context.Background())
			var d *Denial
			if tree != nil || !errors.As(err, &d) || d.Reason != ReasonLimit {
				t.Fatalf("past cap: tree=%v err=%v", tree, err)
			}
			if got := Classify([]byte(tc.past), fakeContext()); got.Allow || got.Reason != ReasonLimit {
				t.Fatalf("past cap decision: %+v", got)
			}
		})
	}
	b := &budget{now: time.Now}
	_ = parse([]byte(nodesAtCap), b)
	if b.nodes != MaxNodes {
		t.Fatalf("node fixture has %d nodes", b.nodes)
	}
	// Resource ownership covers the entire request, not each statement/block.
	src := nested(MaxDepth) + ";" + nested(MaxDepth)
	assertDecision(t, src, true, "")
	assertDecision(t, strings.Repeat("#\n", MaxTokens/2)+"Write-Output x", false, ReasonLimit)
}
func TestLosslessTokensAndDecodedLiterals(t *testing.T) {
	src := []byte("# comment\r\nWrite-Output -InputObject:'it''s literal' |\r\n % { Write-Output \"public\" } 2>&1")
	tree, err := Parse(src, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	end := 0
	for _, token := range tree.Tokens {
		if token.Span.Start < end || token.Span.End > len(src) || token.Text != string(src[token.Span.Start:token.Span.End]) {
			t.Fatalf("invalid token span %+v", token)
		}
		for _, r := range string(src[end:token.Span.Start]) {
			if r != ' ' && r != '\t' {
				t.Fatalf("lost non-whitespace %q", r)
			}
		}
		end = token.Span.End
	}
	if end != len(src) {
		t.Fatal("lost tail")
	}
	c := tree.Script.Pipelines[0].Commands[0]
	if c.Arguments[1].Word.Value != "it's literal" || !c.Arguments[0].Word.Colon {
		t.Fatalf("decoded words: %+v", c.Arguments)
	}
	// Syntax remains lossless, but a block-level merge has no stream proof.
	assertDecision(t, string(src), false, ReasonPipeline)
}
func TestProjectionShapeAndUTF16(t *testing.T) {
	src := []byte("Write-Output '\U00010400' | % { Get-Content -LiteralPath:public } 2> errors")
	got, err := Project(src, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.ParseErrors) != 0 || got.ScriptRequirements != nil || len(got.Unsupported) != 0 || len(got.Bindings) != 3 {
		t.Fatalf("bad projection: %+v", got)
	}
	pipe := got.Statements[0]
	if !reflect.DeepEqual(pipe.Edges, []Edge{{0, 1}}) || pipe.Commands[0].Elements[1].Value != "\U00010400" || pipe.Commands[0].Elements[1].Span != (Span{13, 17}) {
		t.Fatalf("span/edge/literal mismatch: %+v", pipe)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip Projection
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, &roundtrip) {
		t.Fatal("projection JSON shape does not round trip")
	}
	second, err := Project(src, context.Background())
	if err != nil || !reflect.DeepEqual(got, second) {
		t.Fatal("nondeterministic projection", err)
	}
}

type panicContext struct{ context.Context }

func (panicContext) Err() error { panic("SYNTHETIC_PRIVATE_MARKER") }
func TestParseRecovery(t *testing.T) {
	tree, err := Parse([]byte("Write-Output x"), panicContext{context.Background()})
	var d *Denial
	if tree != nil || !errors.As(err, &d) || d.Reason != ReasonPanic {
		t.Fatalf("panic was not contained: %v %v", tree, err)
	}
	result, err := Project([]byte("Write-Output x"), panicContext{context.Background()})
	if result != nil || !errors.As(err, &d) || d.Reason != ReasonPanic {
		t.Fatalf("projection panic was not contained: %v %v", result, err)
	}
}
func TestSignatureLikeComments(t *testing.T) {
	cases := []struct {
		name, comment string
		deny          bool
	}{
		{"extra whitespace", " SIG #  BEGIN SIGNATURE BLOCK", true},
		{"compact", " SIG#BEGINSIGNATUREBLOCK", true},
		{"truncated", " SIG # BEGIN SIGNATURE BLOC", true},
		{"case and tabs", " sIg\t#\tEnD\tSiGnAtUrE\tBlOcK", true},
		{"unicode whitespace", " SIG # BEGIN SIGNATURE BLOCK", true},
		{"marker within prose", " synthetic prefix sig# trailing text", true},
		{"signature within prose", " synthetic prefix SIGNATUREBLOCK trailing text", true},
		{"near begin", " S1G # BEGIN SIGNATUR3 BLOC", true},
		{"near end", " S1G # END SIGNATUR3 BLOC", true},
		{"bounded near prefix", " S1G # BEGIN SIGNATUR3 BLOC " + strings.Repeat("synthetic ", 100), true},
		{"ten deletions", " sinsignature", true},
		{"ordinary", " ordinary comment", false},
		{"empty", "", false},
		{"public prose", " explanatory public prose about harmless input", false},
		{"bounded ordinary", " ordinary comment " + strings.Repeat("synthetic ", 100), false},
	}
	for _, tc := range cases {
		for _, block := range []bool{false, true} {
			name := fmt.Sprintf("%s/block=%v", tc.name, block)
			t.Run(name, func(t *testing.T) {
				comment := "#" + tc.comment + "\n"
				if block {
					comment = "<#" + tc.comment + " #> "
				}
				source := []byte(comment + "Write-Output x")
				tree, err := Parse(source, context.Background())
				if tc.deny {
					var d *Denial
					if tree != nil || !errors.As(err, &d) || d.Reason != ReasonDirective {
						t.Fatalf("signature-like comment: tree=%v err=%v", tree, err)
					}
					assertDecision(t, string(source), false, ReasonDirective)
				} else {
					if err != nil {
						t.Fatal(err)
					}
					assertDecision(t, string(source), true, "")
				}
			})
		}
	}
}

func TestSignatureCommentDeadline(t *testing.T) {
	// Walk every deadline checkpoint in normalization and bounded edit distance.
	text := " ordinary comment " + strings.Repeat("synthetic ", 100)
	checks := 0
	b := &budget{deadline: time.Unix(100, 0), now: func() time.Time { checks++; return time.Unix(0, 0) }}
	if signatureComment(text, b) {
		t.Fatal("ordinary comment rejected")
	}
	total := checks
	for cutoff := 1; cutoff <= total; cutoff++ {
		checks = 0
		b.now = func() time.Time {
			checks++
			if checks >= cutoff {
				return time.Unix(100, 0)
			}
			return time.Unix(0, 0)
		}
		func() {
			var err error
			defer func() {
				var d *Denial
				if !errors.As(err, &d) || d.Reason != ReasonDeadline {
					t.Fatalf("deadline %d/%d: %v", cutoff, total, err)
				}
			}()
			defer recoverDenial(&err)
			signatureComment(text, b)
		}()
	}
}

func TestDecodedStopParsing(t *testing.T) {
	for _, literal := range []string{"--%", "'--%'", `"--%"`} {
		for _, format := range []string{
			"Get-Content %s -Raw", "Get-ChildItem %s -Name", "Write-Output %s",
			"Write-Output -InputObject:%s", "Get-Content -LiteralPath:%s -Raw",
			"Write-Output x > %s", "%s x", "Write-Output x | %% { Write-Output %s }",
		} {
			source := fmt.Sprintf(format, literal)
			t.Run(source, func(t *testing.T) {
				tree, err := Parse([]byte(source), context.Background())
				var d *Denial
				if tree != nil || !errors.As(err, &d) || d.Reason != ReasonUnsupported {
					t.Fatalf("stop-parsing value: tree=%v err=%v", tree, err)
				}
				assertDecision(t, source, false, ReasonUnsupported)
			})
		}
	}
	for _, source := range []string{
		`Get-Content '-dash' -Raw`, `Get-Content "-dash" -Raw`, `Get-ChildItem '-dash' -Name`,
		`Write-Output '--%data'`, `Write-Output "--%data"`, `Write-Output '--'`,
		`Write-Output -InputObject:'-dash'`, `Write-Output x > '-dash'`,
	} {
		if _, err := Parse([]byte(source), context.Background()); err != nil {
			t.Fatal(err)
		}
		assertDecision(t, source, true, "")
	}
}

func FuzzPowerShellParse(f *testing.F) {
	for _, src := range []string{"", `Get-Content public`, `Write-Output 'it''s' | % { Out-Null }`, "#requires -Version 5.1", `Write-Output x 2>&1`, "\xff", "Write-Output -InputObject:'x'"} {
		f.Add([]byte(src))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > MaxSource+1 {
			src = src[:MaxSource+1]
		}
		tree, err := Parse(src, context.Background())
		tree2, err2 := Parse(src, context.Background())
		if (err == nil) != (err2 == nil) || !reflect.DeepEqual(tree, tree2) {
			t.Fatal("nondeterministic parse")
		}
		if err != nil {
			var d *Denial
			if err.Error() != err2.Error() {
				t.Fatal("nondeterministic denial")
			}
			if tree != nil || !errors.As(err, &d) || reasonCategory(d.Reason) == "INVALID" {
				t.Fatal("untyped/incomplete parse", err)
			}
			return
		}
		if len(tree.Tokens) > MaxTokens {
			t.Fatal("token bound exceeded")
		}
		for _, token := range tree.Tokens {
			if token.Span.Start < 0 || token.Span.End > len(src) || token.Span.Start >= token.Span.End {
				t.Fatal("bad span")
			}
		}
	})
}
func FuzzPowerShellAnalyze(f *testing.F) {
	for _, src := range []string{"", `Get-Content public`, `Get-Content protected | Out-Null`, `Write-Output x > config`, `Write-Output x | % { Get-Content public }`, `Get-Content '.\$HOME\public'`} {
		f.Add([]byte(src))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		if len(src) > MaxSource+1 {
			src = src[:MaxSource+1]
		}
		got := Classify(src, fakeContext())
		second := Classify(src, fakeContext())
		if got != second || reasonCategory(got.Reason) == "INVALID" {
			t.Fatal("invalid/nondeterministic decision")
		}
		if got.Allow {
			if got.Reason != "" {
				t.Fatal("allow with denial reason")
			}
			if _, err := Parse(src, context.Background()); err != nil {
				t.Fatal("allow after incomplete parse")
			}
		}
		c, cancel := context.WithCancel(context.Background())
		cancel()
		ctx := fakeContext()
		ctx.Analysis = c
		if Classify(src, ctx).Allow {
			t.Fatal("allow after budget exhaustion")
		}
		called := false
		ctx = fakeContext()
		ctx.ProtectedRead = func(string) bool { called = true; panic("synthetic") }
		ctx.ProtectedWrite = ctx.ProtectedRead
		if got := Classify(src, ctx); got.Allow && called {
			t.Fatal("allow after a failed path proof")
		}
	})
}
