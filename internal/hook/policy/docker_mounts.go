package policy

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// dockerDataOptions consume one data field before image/service selection.
const dockerDataOptions = "--label -l --env -e --env-file --name --hostname -h --user -u --workdir -w " +
	"--entrypoint --network --net --platform --publish -p --expose --add-host --cap-add " +
	"--cap-drop --device --group-add --health-cmd --health-interval --health-retries " +
	"--health-start-period --health-timeout --memory -m --memory-swap --cpus --cpu-shares " +
	"-c --security-opt --ulimit --log-driver --log-opt --restart --runtime --stop-signal " +
	"--stop-timeout --tmpfs --context --config --host -H --tlskey --tlscert --tlscacert " +
	"--opt -o"

// uncertainDockerMount checks uncertainty in mount inputs, not unrelated label,
// message or env-file data. Known inputs still undergo the normal path checks.
func uncertainDockerMount(operands []expandedOperand, knownCWD bool) bool {
	mountOptions := false
	for i := 1; i < len(operands); i++ {
		operand := operands[i]
		value := operand.value
		if !operand.known {
			value = declarationPrefix(operand.source.Parts)
		}
		if operand.known && optionIn(dockerDataOptions, value) {
			i++ // The next field is data, even when it starts with a mount option.
			continue
		}
		if operand.known && value == "--" {
			break
		}
		if !mountOptions {
			mountOptions = operand.known && optionIn("run create", value)
			continue
		}
		if !strings.HasPrefix(value, "-") {
			break // The image/service and its command operands are not host options.
		}
		volume := value == "-v" || strings.HasPrefix(value, "-v") && !strings.HasPrefix(value, "--") || value == "--volume" || strings.HasPrefix(value, "--volume=")
		mount := value == "--mount" || strings.HasPrefix(value, "--mount=")
		if !volume && !mount {
			continue
		}
		if operand.known && optionIn("-v --volume --mount", value) {
			i++
			if i >= len(operands) {
				return true
			}
			operand = operands[i]
		}
		if !operand.known && !(volume && knownCWD && cwdVolumeWord(operand.source)) {
			return true
		}
	}
	return false
}

// cwdVolumeWord recognizes the existing cwd-only Docker volume idioms without
// executing pwd or treating arbitrary substitutions as known input paths.
func cwdVolumeWord(word *syntax.Word) bool {
	var parts []syntax.WordPart
	for _, part := range word.Parts {
		if quoted, ok := part.(*syntax.DblQuoted); ok {
			parts = append(parts, quoted.Parts...)
		} else {
			parts = append(parts, part)
		}
	}
	if len(parts) > 0 {
		if prefix, ok := parts[0].(*syntax.Lit); ok && optionIn("-v --volume=", prefix.Value) {
			parts = parts[1:]
		}
	}
	if len(parts) < 2 {
		return false
	}
	switch first := parts[0].(type) {
	case *syntax.ParamExp:
		if first.Param == nil || first.Param.Value != "PWD" || first.Exp != nil || first.Repl != nil || first.Slice != nil || first.Index != nil || first.Length || first.Excl {
			return false
		}
	case *syntax.CmdSubst:
		if first.Backquotes || len(first.Stmts) != 1 {
			return false
		}
		stmt := first.Stmts[0]
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) != 1 || literal(call.Args[0]) != "pwd" || len(call.Assigns) != 0 || len(stmt.Redirs) != 0 || stmt.Negated || stmt.Background {
			return false
		}
	default:
		return false
	}
	suffix := literal(&syntax.Word{Parts: parts[1:]})
	return strings.HasPrefix(suffix, ":")
}
