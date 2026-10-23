package hook

import (
	"fmt"
	"testing"
)

// Candidate commands are JSON data only. In particular, the printed arithmetic
// text names the same synthetic protected .env fixture as the other hook tests.
func TestArithmeticExpansionOperands(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	contexts := []struct{ name, source string }{
		{"expansion", `echo $((%s))`},
		{"command", `((%s))`},
		{"let", `let "n=%s"`},
		{"declare_integer", `declare -i n="%s"`},
		{"typeset_integer", `typeset -i n="%s"`},
		{"declare_integer_array", `declare -ia arr=("%s")`},
		{"declare_integer_later", `declare -i n; n="%s"`},
		{"typeset_integer_later", `typeset -i n; n="%s"`},
		{"assignment_index", `arr[%s]=1`},
		{"compound_assignment_index", `arr=([%s]=1)`},
		{"parameter_index", `echo "${arr[%s]}"`},
		{"substring_offset", `echo "${x:%s:1}"`},
		{"substring_length", `echo "${x:0:%s}"`},
		{"comparison_eq", `[[ %s -eq 0 ]]`},
		{"comparison_lt", `[[ 0 -lt %s ]]`},
		{"for_init", `for ((i=%s;i<3;i++)); do :; done`},
		{"for_condition", `for ((i=0;i<%s;i++)); do :; done`},
		{"for_post", `for ((i=0;i<3;i+=%s)); do :; done`},
	}
	operands := []struct{ name, source string }{
		{"command_substitution", `$(printf 'arr[$(cat .env)]')`},
		{"numeric_command_substitution", `$(printf 1)`},
		{"variable", `$operand`},
		{"braced_variable", `${operand}`},
		{"backquotes", "`printf 'arr[$(cat .env)]'`"},
	}
	for _, context := range contexts {
		for _, operand := range operands {
			t.Run(context.name+"/"+operand.name, func(t *testing.T) {
				command := fmt.Sprintf(context.source, operand.source)
				for _, value := range []any{command, []string{"bash", "-c", command}} {
					audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, true)
				}
			})
		}
	}
	for _, command := range []string{
		`echo $((1+2))`, `((i++))`, `let "i=1+2"`,
		`declare -i n=1+2`, `typeset -i n=1+2`, `declare -ia arr=(1 2)`,
		`declare -i n; n=1+2`, `typeset -i n; n=1+2`,
		`arr[0]=1`, `arr=([0]=1)`, `echo ${arr[0]}`, `echo ${#a[@]}`,
		`echo ${x:0:1}`, `[[ i -eq 0 ]]`, `[[ 0 -lt i ]]`,
		`for ((i=0;i<3;i++)); do :; done`, `echo $((i+arr[0]))`,
		`echo "$operand"`, `echo "$(printf 1)"`,
	} {
		t.Run("literal/"+command, func(t *testing.T) {
			for _, value := range []any{command, []string{"bash", "-c", command}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, false)
			}
		})
	}
}
