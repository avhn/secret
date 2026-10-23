package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArithmeticWriterCorpus(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("SYNTHETIC=fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../testdata/hook/arithmetic-writers.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name   string
			Tool   string
			Fields map[string]any
			Deny   bool
		}
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			audit28ToolCheck(t, tc.Tool, work, tc.Fields, tc.Deny)
		})
	}
}

// Every source is classifier data. The runtime semantics comparison uses a
// separate disposable Bash fixture, never any of these adapter inputs.
func TestArithmeticWriterOperands(t *testing.T) {
	_, work := audit28ToolsFixture(t)
	writers := []struct{ name, source string }{
		{"read", `n=0; read -r n; @ARITH@`},
		{"read_array", `n=0; read -ra n; @ARITH@`},
		{"read_default", `read; n=REPLY; @ARITH@`},
		{"read_dynamic", `n=0; read "$target"; @ARITH@`},
		{"mapfile", `n=0; mapfile -t n; @ARITH@`},
		{"mapfile_default", `mapfile; n=MAPFILE; @ARITH@`},
		{"readarray", `n=0; readarray -t n; @ARITH@`},
		{"printf", `n=0; printf -v n %s "$operand"; @ARITH@`},
		{"printf_attached", `n=0; printf -vn %s "$operand"; @ARITH@`},
		{"printf_dynamic", `n=0; printf "$flags" n %s "$operand"; @ARITH@`},
		{"getopts", `n=0; getopts a n -a; @ARITH@`},
		{"declare", `n=0; declare "n=$operand"; @ARITH@`},
		{"export", `n=0; export "n=$operand"; @ARITH@`},
		{"local", `f() { n=0; local "n=$operand"; @ARITH@; }; f`},
		{"nameref", `n=0; declare -n ref=n; ref="$operand"; @ARITH@`},
		{"nameref_dynamic", `n=0; declare -n ref="$target"; ref="$operand"; @ARITH@`},
		{"wrapped_read", `n=0; builtin read n; @ARITH@`},
		{"wrapped_printf", `n=0; command printf -v n %s "$operand"; @ARITH@`},
		{"unknown_options", `declare "$flags" n=1; @ARITH@`},
	}
	contexts := []struct{ name, source string }{
		{"expansion", `echo $((n))`},
		{"command", `((n))`},
		{"let", `let n`},
		{"integer", `declare -i result=n`},
		{"assignment_index", `arr[n]=1`},
		{"compound_index", `arr=([n]=1)`},
		{"parameter_index", `echo ${arr[n]}`},
		{"substring_offset", `echo ${x:n:1}`},
		{"substring_length", `echo ${x:0:n}`},
		{"comparison_eq", `[[ n -eq 0 ]]`},
		{"comparison_lt", `[[ 0 -lt n ]]`},
		{"for_init", `for ((i=n;i<3;i++)); do :; done`},
		{"for_condition", `for ((i=0;i<n;i++)); do :; done`},
		{"for_post", `for ((i=0;i<3;i+=n)); do :; done`},
	}
	for _, writer := range writers {
		for _, context := range contexts {
			t.Run(writer.name+"/"+context.name, func(t *testing.T) {
				command := strings.ReplaceAll(writer.source, "@ARITH@", context.source)
				for _, value := range []any{command, []string{"bash", "-c", command}} {
					audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, true)
				}
			})
		}
	}
	for _, tc := range []struct{ name, source string }{
		{"integer_for_expansion", `declare -i n; for n in "$(printf 'arr[$(cat .env)]')"; do :; done`},
		{"integer_for_variable", `declare -i n; for n in "$operand"; do :; done`},
		{"integer_for_literal_expression", `declare -i n; for n in 'arr[$(cat .env)]'; do :; done`},
		{"integer_for_positional", `declare -i n; for n; do :; done`},
		{"integer_read", `declare -i n; read -r n`},
		{"integer_wrapped_declare_read", `command declare -i n; read -r n`},
		{"integer_wrapped_typeset_printf", `builtin typeset -i n; printf -v n %s "$operand"`},
		{"integer_read_array", `declare -i n; read -ra n`},
		{"integer_mapfile", `declare -i n; mapfile -t n`},
		{"integer_readarray", `declare -i n; readarray -t n`},
		{"integer_printf", `declare -i n; printf -v n %s "$operand"`},
		{"integer_getopts", `declare -i n; getopts a n -a`},
		{"integer_nameref", `declare -i n; declare -n ref=n; ref="$operand"`},
		{"integer_later_nameref", `declare -n ref=n; declare -i n; ref="$operand"`},
		{"integer_nameref_read", `declare -i n; declare -n ref=n; read ref`},
		{"integer_unknown_options", `declare "$flags" n="$operand"`},
		{"integer_printf_repeated", `declare -i n; printf -v public -v n %s "$operand"`},
		{"integer_read_initial_default", `declare -i REPLY; read -ei public`},
		{"nameref_index", `read index; declare -n ref='n[index]'; ref=1`},
		{"nameref_unknown_literal", `declare -n ref="$target"; ref=1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, value := range []any{tc.source, []string{"bash", "-c", tc.source}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, true)
			}
		})
	}
	for _, command := range []string{
		`i=0; ((i++))`, `i=0; let 'i++'`, `i=0; echo $((i+1))`,
		`declare -i n; for n in 0 1 2; do :; done`,
		`read -r n; echo "$n"`, `mapfile -t n; echo public`,
		`readarray -t n; echo public`, `printf -v n %s public; echo "$n"`,
		`getopts a n -a; echo "$n"`, `n=0; declare -n ref=n; echo public`,
		`printf %s -v n; echo public`,
		`n=0; declare -n ref=n; ref=1; echo public`,
	} {
		t.Run("control/"+command, func(t *testing.T) {
			for _, value := range []any{command, []string{"bash", "-c", command}} {
				audit28ToolCheck(t, "Bash", work, map[string]any{"command": value}, false)
			}
		})
	}
}
