package policy

import (
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
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

// dockerOption finds the value-taking short option inside a cluster. Flags
// before it do not consume operands; the remaining suffix is its value.
func dockerOption(arg string) (key, value string, attached bool) {
	if !strings.HasPrefix(arg, "-") {
		return arg, "", false
	}
	if strings.HasPrefix(arg, "--") {
		return strings.Cut(arg, "=")
	}
	for i := 1; i < len(arg); i++ {
		key = "-" + arg[i:i+1]
		if optionIn(dockerDataOptions+" -v", key) {
			return key, strings.TrimPrefix(arg[i+1:], "="), i+1 < len(arg)
		}
	}
	return arg, "", false
}

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
		key, _, attached := dockerOption(value)
		if operand.known && optionIn(dockerDataOptions, key) {
			if !attached {
				i++ // The next field is data, even when it starts with a mount option.
			}
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
		volume := optionIn("-v --volume", key)
		mount := key == "--mount"
		if !volume && !mount {
			continue
		}
		if operand.known && !attached {
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

type dockerBind struct{ source, target string }

// dockerBindReaders retains container-to-host aliases while the ordinary child
// dispatcher classifies reader operands. It never opens mount or reader inputs.
func (a *analyzer) dockerBindReaders(args []string, depth int, cwd string) {
	// Global options precede the action; their values are not action words.
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		key, _, attached := dockerOption(args[0])
		args = args[1:]
		if !attached && optionIn(dockerDataOptions, key) {
			if len(args) == 0 {
				a.reason = roles.Indeterminate
				return
			}
			args = args[1:]
		}
	}
	if len(args) == 0 || !optionIn("run create", args[0]) {
		return
	}
	args = args[1:]
	containerCWD := "/"
	var binds []dockerBind
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		if arg == "--" {
			break
		}
		key, value, attached := dockerOption(arg)
		if !optionIn(dockerDataOptions+" -v --volume --mount --pull", key) {
			continue
		}
		if !attached {
			if len(args) == 0 {
				a.reason = roles.Indeterminate
				return
			}
			value, args = args[0], args[1:]
		}
		if optionIn("-w --workdir", key) {
			containerCWD = path.Join("/", value)
			continue
		}
		var source, target string
		if optionIn("-v --volume", key) {
			source, target = dockerVolumePaths(value)
			// A named Docker volume is not a host bind source.
			if !filepath.IsAbs(source) && !strings.HasPrefix(source, ".") && !strings.HasPrefix(source, "~/") {
				continue
			}
		} else if key == "--mount" {
			kind := ""
			for _, field := range strings.Split(value, ",") {
				fieldKey, fieldValue, _ := strings.Cut(field, "=")
				switch fieldKey {
				case "type":
					kind = fieldValue
				case "src", "source":
					source = fieldValue
				case "dst", "destination", "target":
					target = fieldValue
				}
			}
			if kind != "bind" || source == "" {
				// No host source was supplied to this option. Do not borrow
				// CSV fields from later argv words after brace expansion.
				continue
			}
		} else {
			continue
		}
		if source == "" || !path.IsAbs(target) {
			a.reason = roles.Indeterminate
			return
		}
		if a.inputProtected(source, cwd) {
			a.reason = roles.FileInput
			return
		}
		binds = append(binds, dockerBind{a.resolve(source, cwd), path.Clean(target)})
	}
	if len(binds) == 0 || len(args) < 2 {
		return
	}
	probe := *a
	probe.env = maps.Clone(a.env)
	probe.credentialConfigs = slices.Clone(a.credentialConfigs)
	probe.interpreterNames = nil // Host-path literal proofs do not certify container aliases.
	probe.protected = func(name, childCWD string) bool {
		containerPath := name
		if !path.IsAbs(containerPath) {
			containerPath = path.Join(childCWD, containerPath)
		}
		containerPath = path.Clean(containerPath)
		best := -1
		for i, bind := range binds {
			if (containerPath == bind.target || strings.HasPrefix(containerPath, strings.TrimSuffix(bind.target, "/")+"/")) && (best < 0 || len(bind.target) >= len(binds[best].target)) {
				best = i
			}
		}
		if best >= 0 {
			bind := binds[best]
			suffix := strings.TrimPrefix(strings.TrimPrefix(containerPath, bind.target), "/")
			return a.inputProtected(filepath.Join(bind.source, filepath.FromSlash(suffix)), cwd)
		}
		return a.protected(name, childCWD)
	}
	probe.command(args[1:], depth+1, containerCWD, false)
	a.words, a.globs, a.flowSteps = probe.words, probe.globs, probe.flowSteps
	a.uncertain = a.uncertain || probe.uncertain
	a.structuralUncertain = a.structuralUncertain || probe.structuralUncertain
	if probe.reason != "" {
		a.reason = probe.reason
	}
}

// A Windows host drive's colon is part of the source, not the mount separator.
func dockerVolumePaths(value string) (string, string) {
	start := 0
	if len(value) > 2 && value[1] == ':' && (value[2] == '/' || value[2] == '\\') {
		start = 2
	}
	index := strings.IndexByte(value[start:], ':')
	if index < 0 {
		return "", ""
	}
	index += start
	target, _, _ := strings.Cut(value[index+1:], ":")
	return value[:index], target
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
		if prefix, ok := parts[0].(*syntax.Lit); ok {
			key, value, attached := dockerOption(prefix.Value)
			if value == "" && (key == "-v" || key == "--volume" && attached) {
				parts = parts[1:]
			}
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
