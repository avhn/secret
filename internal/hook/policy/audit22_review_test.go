package policy

import "testing"

func TestAudit22InterpreterLaunchReview(t *testing.T) {
	home, work, check := audit21Fixture(t)
	for _, tc := range []struct {
		name, program, code string
		deny                bool
	}{
		{"python floor division", "python3", `import subprocess; n = 4 // 2; subprocess.run(['aws','ecr','get-login-password'])`, true},
		{"python floor division public", "python3", `import subprocess; n = 5 // 2; subprocess.run(['git','status'])`, false},
		{"perl defined or", "perl", `my $x = undef // 0; system('aws','ecr','get-login-password');`, true},
		{"perl defined or public", "perl", `my $x = undef // 0; system('git','status');`, false},
		{"node hash regex", "node", `const re = /#/; require('child_process').spawn('aws', ['ecr','get-login-password'], {stdio:'inherit'})`, true},
		{"node hash regex public", "node", `const re = /#/; require('child_process').spawn('git', ['status'])`, false},
		{"node regex class", "node", `const re = /[/'#]/; require('child_process').spawn('aws', ['ecr','get-login-password'])`, true},
		{"node division", "node", `const n = 4 / 2; require('child_process').spawn('aws', ['ecr','get-login-password'])`, true},
		{"python comment", "python3", "# subprocess.run(['aws','ecr','get-login-password'])\nsubprocess.run(['git','status'])", false},
		{"ruby comment", "ruby", "# system('aws','ecr','get-login-password')\nsystem('git','status')", false},
		{"perl comment", "perl", "# system('aws','ecr','get-login-password');\nsystem('git','status');", false},
		{"node line comment", "node", "// child_process.spawn('aws',['ecr','get-login-password'])\nchild_process.spawn('git',['status'])", false},
		{"node block comment", "node", `/* child_process.spawn('aws',['ecr','get-login-password']) */ child_process.spawn('git',['status'])`, false},
		{"node regex data", "node", `const re = /child_process.spawn('aws',['ecr','get-login-password'])/; child_process.spawn('git',['status'])`, false},
		{"ruby regex data", "ruby", `re = /system('aws','ecr','get-login-password')/; system('git','status')`, false},
		{"perl regex data", "perl", `my $re = /system('aws','ecr','get-login-password')/; system('git','status');`, false},
		{"python comment then launch", "python3", "# public comment\nsubprocess.run(['aws','ecr','get-login-password'])", true},
		{"node comment then launch", "node", "// public comment\nchild_process.spawn('aws',['ecr','get-login-password'])", true},
		{"uncertain parallel child", "python3", `import subprocess; subprocess.run(['parallel','--nonall','aws','ecr','get-login-password'])`, true},
		{"structurally uncertain child", "python3", `subprocess.run(['bash','-c','if true; then'])`, true},
		{"bounded launcher depth", "python3", `subprocess.run(['ionice','ionice','ionice','ionice','git','status'])`, true},
		{"public parallel child", "python3", `subprocess.run(['parallel','-j2','echo',':::','a','b'])`, false},
		{"ordinary launcher prose", "python3", `print('parallel --nonall aws'); print('ionice ionice ionice ionice git status')`, false},
		{"standalone argv data", "python3", `data = ['parallel','--nonall','aws','ecr','get-login-password']`, false},
		{"ruby bare system", "ruby", `system 'aws', 'ecr', 'get-login-password';`, true},
		{"ruby bare exec", "ruby", `exec 'aws', 'ecr', 'get-login-password'`, true},
		{"perl bare system", "perl", `system 'aws', 'ecr', 'get-login-password';`, true},
		{"perl bare exec", "perl", `exec 'aws', 'ecr', 'get-login-password';`, true},
		{"ruby bare public", "ruby", `system 'git', 'status';`, false},
		{"perl bare public", "perl", `exec 'git', 'status';`, false},
		{"ruby bare newline", "ruby", "system 'aws', 'ecr', 'get-login-password'\nputs 'public'", true},
		{"perl bare comment newline", "perl", "system 'aws', 'ecr', 'get-login-password' # public\n;", true},
		{"ruby bare reader", "ruby", `system 'cat', '.env';`, true},
		{"perl bare public reader", "perl", `system 'cat', 'README.md';`, false},
		{"ruby bare expression", "ruby", `system 'echo', 'aws' + ' ecr get-login-password';`, false},
		{"perl bare prose", "perl", `print "system 'aws', 'ecr', 'get-login-password';";`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flag := "-e"
			if tc.program == "python3" {
				flag = "-c"
			}
			for _, source := range []string{
				tc.program + " " + flag + " " + shellLiteral(tc.code),
				tc.program + " <<'SYNTHETIC'\n" + tc.code + "\nSYNTHETIC",
				"printf '%s\\n' " + shellLiteral(tc.code) + " | " + tc.program,
			} {
				if reason := Analyze(source, work, home, check); (reason != "") != tc.deny {
					t.Errorf("%s: reason=%q want deny=%v", source, reason, tc.deny)
				}
			}
			if reason := AnalyzeArgv([]string{tc.program, flag, tc.code}, work, home, check); (reason != "") != tc.deny {
				t.Errorf("argv: reason=%q want deny=%v", reason, tc.deny)
			}
		})
	}
}

func TestAudit22LiteralLaunchDepth(t *testing.T) {
	a := analyzer{literalDepth: 4}
	for _, executable := range []bool{false, true} {
		if got := a.literalCommandProtected([]string{"git", "status"}, "", executable); got != executable {
			t.Errorf("executable=%v: depth-limit protection=%v", executable, got)
		}
		if a.literalCommandProtected(nil, "", executable) {
			t.Error("empty argv supplied an executable witness")
		}
	}
}
