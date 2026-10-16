package roles

import "testing"

func TestAudit23NormalizedCommandAction(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, ""},
		{[]string{"--hostname", "api"}, ""},
		{[]string{"--hostname", "public", "api", "/synthetic"}, "api"},
		{[]string{"--hostname=public", "api", "/synthetic"}, "api"},
		{[]string{"-Rpublic/project", "api", "/synthetic"}, "api"},
		{[]string{"--hostname", "api", "issue", "list"}, "issue"},
		{[]string{"--title", "api", "issue", "list"}, "issue"},
		{[]string{"--template=api", "issue", "list"}, "issue"},
		{[]string{"-Rpublic/project", "--hostname", "api", "api", "/synthetic"}, "api"},
	} {
		if got := CommandAction("gh", tc.args); got != tc.want {
			t.Errorf("%v: action=%q want=%q", tc.args, got, tc.want)
		}
	}
}
