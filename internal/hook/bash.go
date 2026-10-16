package hook

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/policy"
)

// bashDecision applies the bounded AST policy for supported host shell calls.
func bashDecision(e input.Envelope, cwd string, _ func(string) bool) string {
	home := os.Getenv("HOME")
	metadata := new(paths.Metadata)
	check := func(name, dir string) bool {
		// Bare shell operands match the legacy metadata existence check. Paths
		// containing a slash and unresolved aliases retain lexical protection.
		if !strings.Contains(name, "/") {
			if _, err := os.Lstat(paths.Resolve(name, dir, "", home)); os.IsNotExist(err) {
				return false
			}
		}
		return metadata.Protected(name, dir, "", home)
	}
	if raw := e.Fields["command"]; len(raw) != 0 && raw[0] == '[' {
		var argv []string
		if json.Unmarshal(raw, &argv) != nil {
			return "command too complex to analyse for secret access; split it or use secret run"
		}
		return policy.AnalyzeArgv(argv, cwdFor(e, cwd), home, check)
	}
	return policy.Analyze(e.String("command"), cwdFor(e, cwd), home, check)
}

// cwdFor anchors shell operands at an explicit host workdir when supplied.
func cwdFor(e input.Envelope, cwd string) string {
	if dir := e.String("workdir"); dir != "" {
		return paths.Resolve(".", cwd, dir, os.Getenv("HOME"))
	}
	return cwd
}
