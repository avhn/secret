package roles

import "strings"

// Known option values are data, not subcommands. Unknown options may be boolean
// or value-taking: omit the option but retain its possible value, then match
// action words in order. Neither reading can hide a later printer action.
type printerOptions struct {
	unknownPrefix bool
	outputs       []string
	words         []string
	flags         map[string]bool
	values        map[string]string
}

func normalizePrinter(name string, args []string) printerOptions {
	values := ""
	switch name {
	case "aws":
		values = "--profile --region --output --endpoint-url --query --ca-bundle --cli-read-timeout --cli-connect-timeout"
	case "gcloud":
		values = "--project --account --configuration --impersonate-service-account --format --verbosity"
	case "kubectl":
		values = "-n --namespace --context --kubeconfig --cluster --user --server -s --token -o --output"
	case "az":
		values = "--subscription --output -o --query"
	case "doctl":
		values = "--context --config -c --access-token -t --output -o"
	case "heroku":
		values = "--app -a --remote -r"
	case "op":
		values = "--account --session --vault --fields --format"
	case "security":
		values = "-a -s -l -D -G -j -c -C -d -p -r -t"
	case "docker", "docker-compose":
		values = "--context --host -H --config --project-directory --project-name -p --env-file --file -f --format"
	case "gh":
		values = "--host --hostname -h --repo -R --jq --template --title --body"
	case "glab":
		values = "--hostname --host --repo -R"
	case "secret-tool":
		values = "--label"
	case "keyring":
		values = "-b --keyring-backend -p --keyring-path --mode --output"
	case "kwallet-query":
		values = "-r --read-password -f --folder"
	case "xclip":
		values = "-selection -target -t -loops -l -display -d"
	case "xsel":
		values = "--display --selectionTimeout"
	case "npm", "pnpm", "yarn":
		values = "--prefix --workspace --filter --loglevel --registry --userconfig --globalconfig --cwd --dir -C"
	case "php":
		values = "-c --php-ini -d --define -r --run"
	}
	result := printerOptions{flags: make(map[string]bool), values: make(map[string]string)}
	knownValue := func(key string) bool { return strings.Contains(" "+values+" ", " "+key+" ") }
	setValue := func(key, value string) {
		result.values[key] = value
		// Retain every output spelling. Duplicate aliases cannot erase a
		// credential-output witness even when application precedence differs.
		if name == "docker" && (key == "-f" || key == "--format") || name == "kubectl" && (key == "-o" || key == "--output") {
			result.outputs = append(result.outputs, value)
		}
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// A global terminator must not hide positional actions or the
			// options accepted by a later subcommand. An option-looking
			// first action is invalid, not a global option to skip on the
			// way to a later action (for example -- --region ...).
			if len(result.words) == 0 && i+1 < len(args) && strings.HasPrefix(args[i+1], "-") {
				break
			}
			continue
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			result.words = append(result.words, arg)
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		if knownValue(key) {
			if !attached && i+1 < len(args) {
				i++
				value = args[i]
			}
			setValue(key, value)
			continue
		}
		if len(result.words) == 0 && name == "docker" && key != "--debug" && key != "-D" && key != "--tls" && key != "--tlsverify" {
			result.unknownPrefix = true
		}
		if strings.HasPrefix(arg, "--") || name == "xclip" && (arg == "-out" || arg == "-output") {
			if !attached || printerFlag(value) {
				result.flags[key] = true
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			key = "-" + arg[j:j+1]
			if knownValue(key) {
				value = strings.TrimPrefix(arg[j+1:], "=")
				if value == "" && i+1 < len(args) {
					i++
					value = args[i]
				}
				setValue(key, value)
				break
			}
			result.flags[key] = true
		}
	}
	return result
}

// Template and JSONPath variants (including file-backed templates) can expose
// secret data just like JSON/YAML. Name and table output remain metadata roles.
func kubectlContentFormat(format string) bool {
	return format == "json" || format == "yaml" || strings.HasPrefix(format, "jsonpath") ||
		strings.HasPrefix(format, "go-template") || strings.HasPrefix(format, "template") ||
		strings.HasPrefix(format, "custom-columns")
}

func orderedWords(args []string, words ...string) bool {
	for _, arg := range args {
		if len(words) > 0 && arg == words[0] {
			words = words[1:]
		}
	}
	return len(words) == 0
}

// Explicit false spellings disable a boolean flag. True spellings are
// case-insensitive; an unrecognized value cannot erase a printer witness.
func printerFlag(value string) bool {
	switch strings.ToLower(value) {
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func hasOption(args []string, name string) bool {
	for _, arg := range args {
		key, value, attached := strings.Cut(arg, "=")
		if key == name && (!attached || printerFlag(value)) {
			return true
		}
	}
	return false
}

// Single-action CLIs stop interpreting positionals once an action is resolved.
// Unknown global options cannot hide that action, and later data is not a verb.
func printerAction(words []string, actions string) string {
	for _, word := range words {
		if strings.Contains(" "+actions+" ", " "+word+" ") {
			return word
		}
	}
	return ""
}

func makePrintsDatabase(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		key, _, attached := strings.Cut(arg, "=")
		if key == "--print-data-base" {
			return true
		}
		if strings.HasPrefix(arg, "--") {
			if !attached && strings.Contains(" --directory --file --makefile --include-dir --old-file --assume-old --what-if --new-file --assume-new --eval ", " "+key+" ") {
				i++
			}
			continue
		}
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		for j := 1; j < len(arg); j++ {
			if arg[j] == 'p' {
				return true
			}
			if strings.ContainsRune("CfIoWE", rune(arg[j])) {
				if j+1 == len(arg) {
					i++
				}
				break
			}
			if strings.ContainsRune("jlO", rune(arg[j])) {
				break
			}
		}
	}
	return false
}
