// Package hook connects validated host envelopes to shell, file and patch roles.
package hook

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/avhn/secret/internal/hook/input"
	"github.com/avhn/secret/internal/hook/patch"
	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/search"
)

// DecisionTimeout bounds input reading, decoding and analysis together. The
// existing two-second read and policy budgets remain independently enforced.
// Process startup and a blocked host output writer are outside this bound.
const DecisionTimeout = 4 * time.Second

// Decide writes one supported denial or no decision after bounded analysis.
// The installed Bash guard is unchanged; this entry point is the Go hook.
func Decide(host string, in io.Reader, out io.Writer) error {
	return decideWithin(out, DecisionTimeout, func(buffer io.Writer) error {
		return decide(host, in, buffer)
	})
}

// Only this caller writes to the host. An arbitrary Reader or metadata syscall
// cannot be cancelled; a late worker can write only to its private buffer. The
// single-decision CLI exits, and library callers must release blocked readers.
func decideWithin(out io.Writer, timeout time.Duration, analyze func(io.Writer) error) error {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	deadline := time.Now().Add(timeout)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	go func() {
		var buffer bytes.Buffer
		var decision result
		defer func() {
			if recover() != nil {
				decision = result{data: input.Deny("command too complex to analyse for secret access; split it or use secret run", false)}
			}
			done <- decision
		}()
		decision.err = analyze(&buffer)
		decision.data = buffer.Bytes()
	}()
	select {
	case decision := <-done:
		if !time.Now().Before(deadline) {
			_, err := out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
			return err
		}
		if decision.err != nil {
			return decision.err
		}
		if len(decision.data) == 0 {
			return nil
		}
		_, err := out.Write(decision.data)
		return err
	case <-timer.C:
		_, err := out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
	}
}

func decide(host string, in io.Reader, out io.Writer) (err error) {
	data, readErr := input.Read(in)
	if readErr == nil && len(data) == 0 {
		return nil
	}
	e, err := input.Decode(bytes.NewReader(data))
	if readErr != nil || err != nil {
		// A supported host call with an invalid envelope cannot be certified.
		_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
	}
	cwd := e.CWD
	// A relative host cwd cannot anchor a relative workdir or file operand.
	// Native absolute only: on Windows a rooted slash path is drive-relative.
	if !filepath.IsAbs(cwd) || !paths.ValidPath(cwd) {
		_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
	}
	reason := ""
	workdir := ""
	if e.Tool == "apply_patch" {
		workdir = e.String("workdir")
	}
	home := paths.Home()
	if !paths.ValidHome(home) {
		_, err = out.Write(input.Deny("command too complex to analyse for secret access; split it or use secret run", false))
		return err
	}
	protected := func(name string) bool { return paths.FileProtected(name, cwd, workdir, home) }
	switch e.Tool {
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		names := []string{e.String("file_path")}
		if e.Tool == "NotebookEdit" {
			names = []string{e.String("notebook_path")}
		}
		for _, name := range names {
			if name != "" && (protected(name) || e.Tool != "Read" && paths.FileConfigWriteProtected(name, cwd, "", home, os.Getenv("XDG_CONFIG_HOME"), os.Getenv("GIT_CONFIG_GLOBAL"))) {
				reason = "file access targets a protected store"
				break
			}
		}
	case "Glob":
		if !paths.ValidPath(e.String("path")) || paths.NativeProtected(e.String("path"), cwd, "", home) {
			reason = "file access targets a protected store"
		} else {
			reason = search.ToolGlob(e.String("path"), cwd, home)
		}
	case "apply_patch":
		reason = patch.Decision(e.String("command"), cwd, workdir, home)
	case "Grep":
		mode := e.String("output_mode")
		if _, present := e.Fields["output_mode"]; !present {
			mode = "files_with_matches"
		}
		// ToolGrep applies native protection with its names-only symlink rule.
		// A separate identity precheck would deny that retained exception.
		if !paths.ValidPath(e.String("path")) {
			reason = "file access targets a protected store"
		} else {
			reason = search.ToolGrep(e.String("path"), e.String("glob"), e.String("type"), mode, cwd, home)
		}
	case "Bash":
		reason = bashDecision(e, cwd, protected)
	case "PowerShell":
		reason = powershellDecision(host, e, cwd, home)
	default:
		reason = unknownShellDecision(e)
	}
	if reason != "" {
		_, err = out.Write(input.Deny(reason, reason != "command too complex to analyse for secret access; split it or use secret run"))
		return err
	}
	return nil
}
