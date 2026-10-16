package roles

import "strings"

// Known option values are data, not subcommands. Unknown options may be boolean
// or value-taking: omit the option but retain its possible value, then match
// action words in order. Neither reading can hide a later printer action.
func printerArguments(name string, args []string) []string {
	values := ""
	switch name {
	case "aws":
		values = "--profile --region --output --endpoint-url --query --ca-bundle --cli-read-timeout --cli-connect-timeout"
	case "gcloud":
		values = "--project --account --configuration --impersonate-service-account --format --verbosity"
	case "kubectl":
		values = "-n --namespace --context --kubeconfig --cluster --user --server -s --token"
	case "az":
		values = "--subscription --output -o --query"
	case "doctl":
		values = "--context --config --access-token -t --output -o"
	case "heroku":
		values = "--app -a --remote -r"
	}
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break // Subsequent operands cannot introduce a subcommand.
		}
		key, _, attached := strings.Cut(args[i], "=")
		if key != "" && strings.Contains(" "+values+" ", " "+key+" ") {
			if !attached {
				i++
			}
		} else if !strings.HasPrefix(args[i], "-") {
			filtered = append(filtered, args[i])
		}
	}
	return filtered
}

func orderedWords(args []string, words ...string) bool {
	for _, arg := range args {
		if len(words) > 0 && arg == words[0] {
			words = words[1:]
		}
	}
	return len(words) == 0
}

func hasOption(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || arg == name+"=true" {
			return true
		}
	}
	return false
}
