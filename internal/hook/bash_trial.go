//go:build hooktrial

package hook

import (
	"encoding/json"
	"os"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/policy"
)

// bashDecision applies the experimental policy only in tagged trial binaries.
func bashDecision(e input.Envelope, cwd string, _ func(string) bool) string {
	home := os.Getenv("HOME")
	check := func(name, dir string) bool { return paths.Protected(name, dir, "", home) }
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
