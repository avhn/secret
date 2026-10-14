// Package hook connects validated host envelopes to file and patch path roles.
package hook

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/search"
)

// Decide writes a supported denial or no decision. Bash remains unanalysed and
// deferred to the retained guard until the M2 AST implementation is available.
func Decide(host string, in io.Reader, out io.Writer) error {
	data, readErr := io.ReadAll(io.LimitReader(in, input.MaxBytes+1))
	if readErr == nil && len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	e, err := input.Decode(bytes.NewReader(data))
	if readErr != nil || err != nil {
		// A supported host call with an invalid envelope cannot be certified.
		_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
	}
	cwd := e.CWD
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	reason := ""
	workdir := ""
	if e.Tool == "apply_patch" {
		workdir = e.String("workdir")
	}
	protected := func(name string) bool { return paths.Protected(name, cwd, workdir, os.Getenv("HOME")) }
	switch e.Tool {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		name := e.String("file_path")
		if e.Tool == "NotebookEdit" {
			name = e.String("notebook_path")
		}
		if name != "" && protected(name) {
			reason = "file access targets a protected store"
		}
	case "Glob":
		reason = search.ToolGlob(e.String("path"), cwd, os.Getenv("HOME"))
	case "apply_patch":
		if host != "codex" {
			break
		}
		scanner := bufio.NewScanner(strings.NewReader(e.String("command")))
		for scanner.Scan() {
			line := scanner.Text()
			for _, prefix := range []string{"*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: "} {
				if strings.HasPrefix(line, prefix) && protected(strings.TrimPrefix(line, prefix)) {
					reason = "patch targets a protected store"
				}
			}
		}
	case "Grep":
		if host != "claude" {
			break
		}
		reason = search.ToolGrep(e.String("path"), e.String("glob"), e.String("type"), e.String("output_mode"), cwd, os.Getenv("HOME"))
	case "Bash":
		reason = bashDecision(e, cwd, protected)
	}
	if reason != "" {
		_, err = out.Write(input.Deny(reason, reason != "command too complex to analyse for secret access; split it or use secret run"))
		return err
	}
	return nil
}
