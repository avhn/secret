// Package hook connects validated host envelopes to shell, file and patch roles.
package hook

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/patch"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/search"
)

// Decide writes one supported denial or no decision after bounded analysis.
// The installed Bash guard is unchanged; this entry point is the Go hook.
func Decide(host string, in io.Reader, out io.Writer) (err error) {
	defer func() {
		if recover() != nil {
			_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		}
	}()
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
	// A relative host cwd cannot anchor a relative workdir or file operand.
	// Native absolute only: on Windows a rooted slash path is drive-relative.
	if !filepath.IsAbs(cwd) {
		_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
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
		reason = patch.Decision(e.String("command"), cwd, workdir, os.Getenv("HOME"))
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
