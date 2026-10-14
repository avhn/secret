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
		if name := e.String("path"); name != "" && protected(name) {
			reason = "file access targets a protected store"
		}
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
		p := e.String("path")
		if p == "" {
			p = cwd
		}
		mode := e.String("output_mode")
		if mode == "" {
			mode = "files_with_matches"
		}
		selector := e.String("glob")
		fileType := strings.ToLower(e.String("type"))
		if mode != "files_with_matches" && (fileType == "env" || fileType == "dotenv" || fileType == "secret" || fileType == "secrets" || fileType == "netrc" || fileType == "git-credentials") {
			reason = "Grep type targets protected names"
		} else if selector != "" && (protected(selector) || strings.Contains(strings.ToLower(selector), ".env") || strings.Contains(strings.ToLower(selector), ".secret") || strings.Contains(strings.ToLower(selector), ".config/gh/")) && (mode != "files_with_matches" || !strings.ContainsAny(selector, "*?[")) {
			reason = "Grep selector targets protected names"
		} else if protected(p) {
			reason = "Grep targets a protected store"
		} else if mode != "files_with_matches" && paths.TreeProtected(p, cwd, os.Getenv("HOME")) {
			reason = "Grep content/count tree contains protected names or its scan is incomplete (depth, error, deadline); use files_with_matches or narrow the path"
		}
	case "Bash":
		reason = bashDecision(e, cwd, protected)
	}
	if reason != "" {
		_, err = out.Write(input.Deny(reason, reason != "command too complex to analyse for secret access; split it or use secret run"))
		return err
	}
	return nil
}
