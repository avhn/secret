package ps

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// All paths and callback results are synthetic. These tests never inspect a
// real store, provider, environment value or filesystem identity.
func fakeContext() Context {
	return Context{
		Cwd: `C:\work`, Home: `C:\home`,
		ProtectedRead: func(p string) bool {
			p = strings.ToLower(p)
			return strings.Contains(p, `\protected`) || strings.Contains(p, `\.secrets`)
		},
		ProtectedWrite: func(p string) bool { return strings.Contains(strings.ToLower(p), `\config`) },
		CertifyPath: func(p string, k FileKind) bool {
			return !strings.Contains(p, "uncertain") && !strings.Contains(p, "link")
		},
	}
}
func assertDecision(t *testing.T, source string, want bool, reason string) {
	t.Helper()
	got := Classify([]byte(source), fakeContext())
	if got.Allow != want || reason != "" && got.Reason != reason || want && got.Reason != "" {
		t.Fatalf("decision for synthetic %q = %+v; want allow=%v reason=%q", source, got, want, reason)
	}
}
func TestPairedPathRoles(t *testing.T) {
	cases := []struct {
		name, format string
		reason       string
	}{
		{"reader", `Get-Content -LiteralPath '%s'`, ReasonRead},
		{"reader positional", `Get-Content '%s'`, ReasonRead},
		{"search", `Select-String -Pattern 'config is data' -LiteralPath '%s'`, ReasonRead},
		{"names", `Get-ChildItem -Name -LiteralPath '%s'`, ReasonRead},
		{"copy source", `Copy-Item -LiteralPath '%s' -Destination out.txt`, ReasonRead},
		{"copy destination", `Copy-Item public.txt -Destination '%s'`, ReasonWrite},
		{"set", `Set-Content -LiteralPath '%s' -Value '.secrets is data'`, ReasonWrite},
		{"add", `Write-Output 'payload' | Add-Content -LiteralPath '%s'`, ReasonWrite},
		{"out", `Get-Content public.txt | Out-File '%s'`, ReasonWrite},
		{"redirect", `Write-Output '.secrets is data' > '%s'`, ReasonWrite},
		{"nested", `Write-Output x | ForEach-Object { Get-Content '%s' }`, ReasonRead},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertDecision(t, fmt.Sprintf(tc.format, "public.txt"), true, "")
			assertDecision(t, fmt.Sprintf(tc.format, "protected.txt"), false, tc.reason)
		})
	}
	for _, format := range []string{`Set-Content '%s' x`, `Add-Content '%s' x`, `Copy-Item public '%s'`, `Write-Output x | Out-File '%s'`, `Write-Output x > '%s'`} {
		assertDecision(t, fmt.Sprintf(format, "public.txt"), true, "")
		assertDecision(t, fmt.Sprintf(format, "config.txt"), false, ReasonWrite)
	}
}
func TestBindingsAndLiterals(t *testing.T) {
	allow := []string{
		"", "# ordinary comment\r\n", "Write-Output x; Out-Null\nWrite-Output y",
		"<# ordinary block comment #> Write-Output x", "<# outer #> Write-Output x <# trailing #>",
		"Write-Output x | % { <# block\r\n comment #> Write-Output y }",
		`Write-Output 'it''s literal'`, `Write-Output "non expanding"`, `Write-Output '-Path'`,
		"Write-Output 'first\nsecond'", "Write-Output \"first\r\nsecond\"",
		`Write-Output -InputObject:'-dash'`, `Write-Output -InputObject x`,
		`Get-Content -LiteralPath:public.txt`, `Get-Content -Path:'public.txt' -Raw`,
		`Get-Content '01'`, `Get-Content '0x10'`, `Get-Content '1e2'`, `Get-Content '+1'`, `Get-Content '.1'`,
		`Select-String pattern public.txt`, `Select-String -Path public.txt 'literal pattern' -SimpleMatch -CaseSensitive`,
		`Copy-Item -Destination dest.txt public.txt`, `Copy-Item -LiteralPath public.txt dest.txt`,
		`Set-Content -LiteralPath public.txt '-dash data'`, `Set-Content -Value x public.txt`,
		`Write-Output x | Set-Content public.txt`, `Write-Output x | Add-Content -Path:public.txt`,
		`Write-Output x | Out-File -FilePath public.txt -Append`,
		`Write-Output x | ForEach-Object -Process { Write-Output y }`,
		`Write-Output x | % { Get-Content public.txt | Out-Null; Write-Output y } | Out-Null`,
		"Get-Content public.txt | # comment\r\n Out-Null",
		`Write-Output 'C:\protected.txt is just data'`,
		`Select-String -LiteralPath public.txt -Pattern 'C:\protected.txt'`,
		`Write-Output 'snowman \u2603'`,
	}
	for _, src := range allow {
		assertDecision(t, src, true, "")
	}
	denyCases := []string{
		`Get-Content`, `Get-Content -Lit public.txt`, `Get-Content -LiteralPath public.txt -ErrorAction Stop`,
		`Get-Content -LiteralPath a -Path b`, `Get-Content -Path a -Path b`, `Get-Content a b`,
		`Get-Content -Wait public.txt`, `Get-Content -Encoding Byte public.txt`, `Get-Content -Stream x public.txt`,
		`Get-Content -Raw:$true public.txt`, `Get-Content -Raw:foo public.txt`,
		`Select-String -Pattern x`, `Select-String -InputObject x -Pattern x`,
		`Get-ChildItem public`, `Get-ChildItem -Name -Recurse public`,
		`Copy-Item public`, `Copy-Item public dest -Recurse`, `Copy-Item public dest -Container`, `Copy-Item public dest -ToSession x`,
		`Set-Content public`, `Set-Content public -Value`, `Set-Content public x y`,
		`Write-Output x | Set-Content public -Value y`, `Write-Output x | Get-Content public`,
		`Write-Output x | Out-Null | Get-Content public`, `Write-Output x | Out-Null | Write-Output y`,
		`Write-Output public | Select-String x`, `Write-Output public | Copy-Item -Destination dest`,
		`Out-File public`, `ForEach-Object { Write-Output x }`,
		`Write-Output x | ForEach-Object { Write-Output y } { Write-Output z }`,
		`Write-Output x | ForEach-Object -Begin { Write-Output y }`,
		`Write-Output x | ForEach-Object -Parallel { Write-Output y }`,
		`Write-Output x | ForEach-Object -MemberName Length`, `Write-Output { Get-Content protected }`,
		`Get-Content protected | Out-Null`, `Get-Content protected > public`,
		`Write-Output x | ForEach-Object { Get-Content protected | Out-Null }`,
		`Get-Content -LiteralPath: public`, `Write-Output -InputObject:x -InputObject y`,
		`Write-Output a b`, `Write-Output -NoEnumerate x`,
	}
	for _, src := range denyCases {
		assertDecision(t, src, false, "")
	}
}
func TestAliasesAndCase(t *testing.T) {
	for alias, canonical := range aliases {
		var tail string
		switch canonical {
		case "get-content":
			tail = " '%s'"
		case "select-string":
			tail = " -Pattern x -LiteralPath '%s'"
		case "get-childitem":
			tail = " -Name -LiteralPath '%s'"
		case "copy-item":
			tail = " -LiteralPath '%s' -Destination public"
		case "foreach-object":
			for _, spelling := range []string{alias, strings.ToUpper(alias)} {
				assertDecision(t, `Write-Output x | `+spelling+` { Get-Content public }`, true, "")
				assertDecision(t, `Write-Output x | `+spelling+` { Get-Content protected }`, false, ReasonRead)
			}
			continue
		}
		for _, spelling := range []string{alias, strings.ToUpper(alias)} {
			assertDecision(t, fmt.Sprintf(spelling+tail, "public"), true, "")
			assertDecision(t, fmt.Sprintf(spelling+tail, "protected"), false, ReasonRead)
			if canonical == "copy-item" {
				assertDecision(t, spelling+" public protected", false, ReasonWrite)
				assertDecision(t, spelling+" public config", false, ReasonWrite)
			}
		}
	}
	assertDecision(t, `gEt-CoNtEnT -lItErAlPaTh PUBLIC`, true, "")
	assertDecision(t, `gEt-CoNtEnT -lItErAlPaTh PROTECTED`, false, ReasonRead)
	assertDecision(t, `echo x`, false, ReasonCommand)
}
func TestProhibitedConstructs(t *testing.T) {
	cases := []string{
		`Invoke-Expression 'Get-Content protected'`, `iex x`, `. public.ps1`, `& Get-Content public`,
		`$command public`, `$(Get-Content public)`, `Write-Output $HOME`, `Write-Output "${HOME}"`,
		`Write-Output @args`, `Write-Output @(1)`, `Write-Output @{x=1}`, "Write-Output @'\nx\n'@",
		"Write-Output @\"\nx\n\"@", `Start-Process public`, `Start-Job { Get-Content protected }`,
		`Invoke-Command { Get-Content public }`, `[runspacefactory]::CreateRunspace()`,
		`Import-Module public`, `Add-Type public`, `New-Object public`, `Get-Credential`,
		`Set-Alias gc Write-Output`, `function gc { Write-Output x }`, `class X {}`,
		`foreach ($x in 1) { Write-Output x }`, `while (1) { Write-Output x }`, `if (1) { Write-Output x }`,
		`trap { Write-Output x }`, `param($x)`, `Write-Output x | ForEach-Object { $_ }`,
		`Write-Output x | ForEach-Object { $PSItem }`, `{ Write-Output x }`,
		`Write-Output x --% ignored`, `Write-Output -- x`, `powershell -EncodedCommand AA==`,
		`pwsh -e AA==`, `cmd /c type public`, `public.bat`, `wsl cat public`, `bash -c x`,
		`secret get public X`, `aws configure list`, `curl public`, `G*-Content public`,
		`Microsoft.PowerShell.Management\Get-Content public`,
		`Get-Content Env:HOME`, `Get-Content Cert:\currentuser`, `Get-Content HKCU:\x`,
		`Get-Content Variable:x`, `Get-Content Function:x`, `Get-Content Alias:x`, `Get-Content Custom:\x`,
		`Get-Content FileSystem::C:\public`, `Get-Content C:public`, `Get-Content '\public'`,
		`Get-Content 'C:\public:stream'`, `Get-Content '\\?\C:\public'`, `Get-Content '\\.\pipe\public'`,
		`Get-Content 'C:\NUL'`, `Get-Content 'C:\NUL .txt'`, `Get-Content 'C:\file. '`, `Get-Content 'C:\file.'`,
		`Get-Content 01`, `Get-Content 0x10`, `Get-Content 1e2`, `Get-Content +1`, `Get-Content .1`,
		`Get-Content 'C:\COM1.txt'`, `Get-Content 'C:\COM¹.txt'`,
		`Get-Content '*.txt'`, `Get-Content -LiteralPath 'file[0]'`,
		`Set-Location public`, `New-PSDrive x`, `New-Item -ItemType SymbolicLink public`,
		"Write-Output x`n", "Write-Output `\n x", "Write-Output 'literal`tick'",
		`Write-Output 'a'"b"`, `Write-Output "a"'b'`, `Write-Output foo'bar'`,
		"Write-Output \u201cx\u201d", "Get\u2013Content public", "Write-Output x\x00", "Write-Output x\x1b", "Write-Output x\u200b",
		"<# unterminated block comment", "<# outer <# nested #>", "Write-Output <# outer <# nested #> comment #> x",
		"Write-Output <# <# #> ; Get-Content protected #>", "#requires -Version 5.1\nWrite-Output x",
		"Write-Output x\n#Requires -Modules Synthetic", "Write-Output x | % {\n#requires -Version 5.1\n Write-Output y }",
		"# SIG # Begin signature block\n# synthetic\n# SIG # End signature block",
		"Write-Output x | % { # SIG # Begin signature block\n Write-Output y }",
	}
	for _, src := range cases {
		assertDecision(t, src, false, "")
	}
	for _, src := range []string{`Write-Output '`, `Write-Output "`, `Write-Output x |`, `Write-Output x | ;`,
		`Write-Output x && Write-Output y`, `Write-Output x || Write-Output y`, `Write-Output x ; }`,
		`Write-Output x | % { Write-Output y`, `Write-Output x >`, "Get-Content public.txt # comment\r\n| Out-Null",
		"Write-Output x\r", string([]byte{0xed, 0xa0, 0x80}), string([]byte{0xff})} {
		assertDecision(t, src, false, "")
	}
}
func TestRedirects(t *testing.T) {
	for _, prefix := range []string{"", "1", "2", "3", "4", "5", "6", "*"} {
		for _, op := range []string{">", ">>"} {
			assertDecision(t, "Write-Output x "+prefix+op+" public", true, "")
			assertDecision(t, "Write-Output x "+prefix+op+" protected", false, ReasonWrite)
			assertDecision(t, "Write-Output x "+prefix+op+" config", false, ReasonWrite)
		}
	}
	for _, stream := range []string{"2", "3", "4", "5", "6", "*"} {
		assertDecision(t, "Write-Output x "+stream+">&1", true, "")
	}
	for _, tail := range []string{"< public", "0> public", "7> public", "2>&2", "1>&1", "2>>&1", "2>&10", "2>&1foo", "> $HOME", "> Env:HOME", "> '*.txt'", "> public > other", "*> public 2> other", "2> public *> other", "2>&1 2> public", ">public", "1>public"} {
		assertDecision(t, "Write-Output x "+tail, false, "")
	}
	assertDecision(t, `Write-Output x 2> public > other`, true, "")
	assertDecision(t, `Write-Output x > public | Out-File other`, false, ReasonPipeline)
}
func TestNativeAnchoring(t *testing.T) {
	// Different synthetic environment homes must not affect literal anchoring.
	t.Setenv("HOME", `D:\different-home`)
	t.Setenv("USERPROFILE", `E:\different-userprofile`)
	cases := []struct {
		source, cwd, home, wantPath string
		allow                       bool
	}{
		{`Get-Content '.\$HOME\public'`, `C:\work`, `D:\different-home`, `C:\work\.\$HOME\public`, true},
		{`Get-Content '.\$HOME\protected'`, `C:\work`, `D:\different-home`, `C:\work\.\$HOME\protected`, false},
		{`Set-Content '.\$HOME\public' x`, `C:\work`, `D:\different-home`, `C:\work\.\$HOME\public`, true},
		{`Set-Content '.\$HOME\protected' x`, `C:\work`, `D:\different-home`, `C:\work\.\$HOME\protected`, false},
		{`Get-Content public`, `C:\protected`, `D:\different-home`, `C:\protected\public`, false},
		{`Set-Content public x`, `C:\protected`, `D:\different-home`, `C:\protected\public`, false},
		{`Get-Content public`, `C:\work`, `D:\different-home`, `C:\work\public`, true},
		{`Get-Content 'D:\public'`, `C:\work`, `D:\different-home`, `D:\public`, true},
		{`Get-Content '\\server\share\public'`, `C:\work`, `D:\different-home`, `\\server\share\public`, true},
		{`Get-Content 'link\..\public'`, `C:\work`, `D:\different-home`, `C:\work\link\..\public`, true},
	}
	for _, tc := range cases {
		t.Run(tc.source+tc.cwd, func(t *testing.T) {
			ctx := fakeContext()
			ctx.Cwd = tc.cwd
			ctx.Home = tc.home
			var seen []string
			read := ctx.ProtectedRead
			ctx.ProtectedRead = func(p string) bool { seen = append(seen, p); return read(p) }
			got := Classify([]byte(tc.source), ctx)
			if got.Allow != tc.allow || len(seen) == 0 || seen[0] != tc.wantPath {
				t.Fatalf("got %+v paths=%q want %v %q", got, seen, tc.allow, tc.wantPath)
			}
		})
	}
	for _, operand := range []string{`'$HOME/public'`, `'~/public'`, `'$env:USERPROFILE/public'`, `'.\${HOME}\public'`} {
		assertDecision(t, "Get-Content "+operand, false, ReasonPath)
		assertDecision(t, "Set-Content "+operand+" x", false, ReasonPath)
	}
	for _, cwd := range []string{"", `C:relative`, `\rooted`, `Env:HOME`, `C:\bad:ads`, `C:\NUL`, `C:\trimmed.`, `C:\a` + "\x00"} {
		ctx := fakeContext()
		ctx.Cwd = cwd
		if got := Classify([]byte("Write-Output x"), ctx); got.Allow || got.Reason != ReasonContext {
			t.Fatalf("invalid cwd %q: %+v", cwd, got)
		}
	}
}
func TestMetadataRoleRequests(t *testing.T) {
	type request struct {
		Path string
		Kind FileKind
	}
	cases := []struct {
		source string
		want   []request
	}{
		{`Copy-Item source destination`, []request{{`C:\work\source`, RegularFile}, {`C:\work\destination`, NonDirectory}}},
		{`Get-ChildItem -Name directory`, []request{{`C:\work\directory`, Directory}}},
	}
	for _, tc := range cases {
		ctx := fakeContext()
		var got []request
		ctx.CertifyPath = func(path string, kind FileKind) bool { got = append(got, request{path, kind}); return true }
		decision := Classify([]byte(tc.source), ctx)
		if !decision.Allow || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("metadata requests %+v: %v want %v", decision, got, tc.want)
		}
	}
}

func TestCertificationAndFailureOwnership(t *testing.T) {
	for _, src := range []string{`Copy-Item public dest`, `Get-ChildItem -Name public`} {
		for _, mode := range []string{"nil", "false", "panic", "cancel"} {
			ctx := fakeContext()
			c, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx.Analysis = c
			switch mode {
			case "nil":
				ctx.CertifyPath = nil
			case "false":
				ctx.CertifyPath = func(string, FileKind) bool { return false }
			case "panic":
				ctx.CertifyPath = func(string, FileKind) bool { panic("SYNTHETIC_PRIVATE_MARKER") }
			case "cancel":
				ctx.CertifyPath = func(string, FileKind) bool { cancel(); return true }
			}
			got := Classify([]byte(src), ctx)
			if got.Allow || strings.Contains(got.Reason, "MARKER") {
				t.Fatalf("%s %s: %+v", mode, src, got)
			}
		}
	}
	for _, which := range []string{"read", "write", "clock", "typed"} {
		ctx := fakeContext()
		fault := func(string) bool { panic("SYNTHETIC_PRIVATE_MARKER") }
		switch which {
		case "read":
			ctx.ProtectedRead = fault
		case "write":
			ctx.ProtectedWrite = fault
		case "clock":
			ctx.Deadline = time.Now()
			ctx.Now = func() time.Time { panic("SYNTHETIC_PRIVATE_MARKER") }
		case "typed":
			ctx.ProtectedRead = func(string) bool { panic(&Denial{Reason: "SYNTHETIC_PRIVATE_MARKER"}) }
		}
		got := Classify([]byte(`Set-Content public x`), ctx)
		if got.Allow || got.Reason != ReasonPanic {
			t.Fatalf("panic %s: %+v", which, got)
		}
	}
	for _, which := range []string{"read", "write"} {
		ctx := fakeContext()
		if which == "read" {
			ctx.ProtectedRead = nil
		} else {
			ctx.ProtectedWrite = nil
		}
		if got := Classify([]byte(`Write-Output x`), ctx); got.Allow || got.Reason != ReasonContext {
			t.Fatalf("nil %s: %+v", which, got)
		}
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	tree, err := Parse([]byte(`Get-Content public`), c)
	var d *Denial
	if tree != nil || !errors.As(err, &d) || d.Reason != ReasonDeadline {
		t.Fatalf("canceled parse: %v %v", tree, err)
	}
	ctx := fakeContext()
	ctx.Analysis = c
	if got := Classify([]byte(`Write-Output x`), ctx); got.Reason != ReasonDeadline || got.Allow {
		t.Fatalf("canceled analysis: %+v", got)
	}
	// Exhaust deterministically at scan, parse, bind, walk and the final check.
	src := []byte(`Write-Output x | % { Get-Content public } | Out-Null`)
	ctx = fakeContext()
	ctx.Deadline = time.Unix(100, 0)
	checks := 0
	ctx.Now = func() time.Time { checks++; return time.Unix(0, 0) }
	if got := Classify(src, ctx); !got.Allow {
		t.Fatalf("control: %+v", got)
	}
	total := checks
	for cutoff := 1; cutoff <= total; cutoff++ {
		checks = 0
		ctx.Now = func() time.Time {
			checks++
			if checks >= cutoff {
				return time.Unix(100, 0)
			}
			return time.Unix(0, 0)
		}
		if got := Classify(src, ctx); got.Allow || got.Reason != ReasonDeadline {
			t.Fatalf("deadline %d/%d: %+v", cutoff, total, got)
		}
	}
	// Cancellation inside an otherwise successful path callback cannot allow.
	c, cancel = context.WithCancel(context.Background())
	defer cancel()
	ctx = fakeContext()
	ctx.Analysis = c
	ctx.ProtectedRead = func(string) bool { cancel(); return false }
	if got := Classify([]byte(`Get-Content public`), ctx); got.Allow || got.Reason != ReasonDeadline {
		t.Fatalf("post-callback cancel: %+v", got)
	}
}
func TestSyntheticCorpus(t *testing.T) {
	f, err := os.Open("../../../testdata/hook/powershell/cases.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		count++
		var row struct {
			Source   string `json:"source"`
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		got := Classify([]byte(row.Source), fakeContext())
		if row.Decision != "allow" && row.Decision != "deny" {
			t.Fatalf("invalid decision row %d", count)
		}
		if got.Allow != (row.Decision == "allow") || reasonCategory(got.Reason) != row.Reason {
			t.Fatalf("row %d: %+v want %s %s", count, got, row.Decision, row.Reason)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 20 {
		t.Fatal("corpus unexpectedly small")
	}
}
func reasonCategory(reason string) string {
	switch reason {
	case "":
		return "safe"
	case ReasonSyntax:
		return "syntax"
	case ReasonUnsupported:
		return "unsupported"
	case ReasonDirective:
		return "directive"
	case ReasonBinding:
		return "binding"
	case ReasonCommand:
		return "command"
	case ReasonPipeline:
		return "pipeline"
	case ReasonPath:
		return "path"
	case ReasonRead:
		return "protected-read"
	case ReasonWrite:
		return "protected-write"
	case ReasonMetadata:
		return "metadata"
	case ReasonDeadline:
		return "deadline"
	case ReasonLimit:
		return "limit"
	case ReasonContext:
		return "context"
	case ReasonPanic:
		return "failure"
	}
	return "INVALID"
}
func TestDecisionDeterminism(t *testing.T) {
	src := []byte(`Write-Output x | % { Get-Content public } | Out-File destination`)
	first := Classify(src, fakeContext())
	for i := 0; i < 100; i++ {
		if got := Classify(src, fakeContext()); !reflect.DeepEqual(got, first) {
			t.Fatalf("nondeterministic: %+v %+v", first, got)
		}
	}
}
