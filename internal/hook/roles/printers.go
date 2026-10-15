package roles

import "strings"

// Consume known global options throughout the command hierarchy. Option values
// are data, not subcommands; unknown options and -- retain their action slots.
func printerArguments(name string, args []string) []string {
	values, flags := "", ""
	switch name {
	case "aws":
		values = "--profile --region --output --endpoint-url --query --ca-bundle --cli-read-timeout --cli-connect-timeout"
		flags = "--no-cli-pager --no-paginate --debug --no-verify-ssl"
	case "gcloud":
		values = "--project --account --configuration --impersonate-service-account --format --verbosity"
		flags = "--quiet -q"
	case "kubectl":
		values = "-n --namespace --context --kubeconfig --cluster --user --server -s --token"
	case "az":
		values = "--subscription --output -o --query"
		flags = "--only-show-errors --debug --verbose"
	case "doctl":
		values = "--context --config --access-token -t --output -o"
		flags = "--verbose -v"
	case "heroku":
		values = "--app -a --remote -r"
	}
	if values == "" && flags == "" {
		return args
	}
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			return append(filtered, args[i:]...)
		}
		key, _, attached := strings.Cut(args[i], "=")
		if key != "" && strings.Contains(" "+values+" ", " "+key+" ") {
			if !attached {
				if i+1 >= len(args) {
					return append(filtered, args[i])
				}
				i++
			}
		} else if key == "" || !strings.Contains(" "+flags+" ", " "+key+" ") {
			filtered = append(filtered, args[i])
		}
	}
	return filtered
}

func hasOption(args []string, name string) bool {
	for _, arg := range args {
		if arg == name || arg == name+"=true" {
			return true
		}
	}
	return false
}
