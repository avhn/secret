package feature

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/avhn/secret/internal/store"
)

var ErrCompletion = errors.New("invalid completion request or metadata")

// CompletionRequest selects static commands/flags or names from caller-supplied
// metadata. Flag is reference, --key, --optional-key or --label for dynamic names;
// an empty Flag selects commands or the specified command's static flags.
// Results are literal candidates, not executable shell source.
type CompletionRequest struct {
	Command   string
	Flag      string
	Prefix    string
	Selectors store.Selectors
}

var completionCommands = []string{"audit", "clip", "completion", "delete", "diff", "doctor", "exec", "export", "get", "hook", "import", "list", "mcp", "rename", "rotate", "run", "show", "stash", "version"}

var completionFlags = map[string][]string{
	"audit": {"--action", "--key", "--limit", "--outcome", "--target", "--format=json"},
	"clip":  {"--env", "--label"}, "completion": {},
	"delete": {"--env", "--label"}, "diff": {"--env", "--label", "--format=json"},
	"doctor": {"--format=json"}, "exec": {"--env", "--key", "--label", "--optional-key"},
	"export": {"--from", "--to", "--env", "--key", "--label", "--on-conflict=fail", "--dry-run"},
	"get":    {"--env", "--label"}, "hook": {},
	"import": {"--from", "--into", "--label", "--map", "--dry-run"},
	"list":   {"--format=json"}, "mcp": {}, "rename": {"--env", "--label"},
	"rotate": {"--env", "--label"}, "run": {"--env", "--key", "--label", "--optional-key", "--template-file"},
	"show": {"--env", "--label", "--format=json"}, "stash": {"--env", "--label"}, "version": {},
}

// Complete never opens a store or invokes a provider. Callers supply only the
// explicitly scoped metadata they intend to expose. With selectors, key names
// include matched records only; without selectors all known key names qualify.
func Complete(request CompletionRequest, metadata []store.Metadata) ([]string, error) {
	if !safeMetadataText(request.Prefix, 4096, true) || validateMetadataSelectors(request.Selectors) != nil {
		return nil, ErrCompletion
	}
	flags, known := completionFlags[request.Command]
	if request.Command != "" && !known {
		return nil, ErrCompletion
	}
	candidates := make(map[string]bool)
	add := func(candidate string) {
		if strings.HasPrefix(candidate, request.Prefix) {
			candidates[candidate] = true
		}
	}
	if request.Flag == "" {
		if request.Command == "" {
			flags = completionCommands
		}
		for _, flag := range flags {
			add(flag)
		}
	} else {
		switch request.Flag {
		case "reference", "--from", "--to", "--into", "--key", "--optional-key", "--label":
		default:
			return nil, ErrCompletion
		}
		for _, item := range metadata {
			if validateMetadata(item) != nil || !safeMetadataText(item.Reference, 4096, false) {
				return nil, ErrCompletion
			}
			switch request.Flag {
			case "reference", "--from", "--to", "--into":
				if request.Command == "import" && request.Flag == "--from" {
					path := strings.TrimPrefix(item.Reference, "file:")
					if item.Backend == "file" && validOperatorReference("file:"+path) {
						add("dotenv:" + path)
					}
				} else if (request.Flag != "--to" || item.Backend != "file") && !(item.Backend == "onepassword" && (request.Flag == "--to" || request.Flag == "--into" || request.Command == "export")) {
					add(item.Reference)
				}
			case "--key", "--optional-key":
				if len(request.Selectors) == 0 {
					for _, record := range item.Records {
						add(record.Key)
					}
				} else {
					selection, err := SelectMetadata(item, request.Selectors)
					if err != nil {
						return nil, ErrCompletion
					}
					for key := range selection.Matched {
						add(key)
					}
				}
			case "--label":
				for _, record := range item.Records {
					for name, value := range record.Labels {
						add(name + "=" + value)
					}
				}
			}
		}
	}
	result := make([]string, 0, len(candidates))
	for candidate := range candidates {
		result = append(result, candidate)
	}
	sort.Strings(result)
	return result, nil
}

func safeMetadataText(text string, limit int, empty bool) bool {
	if (!empty && text == "") || len(text) > limit || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

func absoluteMetadataPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path
}

// explicitMetadataReference is syntax-only. It never resolves or probes a path.
func explicitMetadataReference(reference string) bool {
	if !safeMetadataText(reference, 4096, false) {
		return false
	}
	if strings.HasPrefix(reference, "file:") {
		return absoluteMetadataPath(strings.TrimPrefix(reference, "file:"))
	}
	if strings.HasPrefix(reference, "keychain:") || strings.HasPrefix(reference, "libsecret:") || strings.HasPrefix(reference, "onepassword:") {
		_, err := (store.Locator{}).Resolve(reference)
		return err == nil
	}
	return false
}
