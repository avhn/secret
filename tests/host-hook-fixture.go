//go:build hosthookfixture && (linux || darwin)

// This synthetic host fault executable is built explicitly by host-hooks.yml.
// It is excluded from ordinary ./... builds and must never be released.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("secret 0.5.0 (go)")
		return
	}
	var mode, record, binary string
	if len(os.Args) == 4 {
		mode, record, binary = os.Args[1], os.Args[2], os.Args[3]
	} else if len(os.Args) == 3 && os.Args[1] == "hook" && os.Args[2] == "claude" {
		// Only the unshipped fixture build accepts these synthetic controls.
		mode = os.Getenv("SECRET_HOST_FIXTURE_MODE")
		record = os.Getenv("SECRET_HOST_FIXTURE_RECORD")
		binary = os.Getenv("SECRET_HOST_FIXTURE_BINARY")
	} else {
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if err != nil || len(data) > 65536 {
		os.Exit(2)
	}
	var envelope struct {
		Event string `json:"hook_event_name"`
		Tool  string `json:"tool_name"`
		CWD   string `json:"cwd"`
		Input struct {
			Workdir string `json:"workdir"`
		} `json:"tool_input"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		os.Exit(2)
	}
	cwd, err := os.Getwd()
	if err != nil {
		os.Exit(2)
	}
	// Persist names-only envelope facts, never tool input, output or environment.
	facts := struct {
		Event          string `json:"event"`
		Tool           string `json:"tool"`
		CWDMatches     bool   `json:"cwd_matches"`
		CWDAbsolute    bool   `json:"cwd_absolute"`
		WorkdirPresent bool   `json:"workdir_present"`
	}{envelope.Event, envelope.Tool, envelope.CWD == cwd,
		filepath.IsAbs(envelope.CWD), envelope.Input.Workdir != ""}
	encoded, err := json.Marshal(facts)
	if err != nil || os.WriteFile(record, append(encoded, '\n'), 0600) != nil {
		os.Exit(2)
	}
	switch mode {
	case "probe":
		return
	case "neutral":
		fmt.Println(`{"hookSpecificOutput":{"hookEventName":"PreToolUse"}}`)
	case "empty":
		// Successful empty output is a separate residual-risk control.
		return
	case "deny":
		fmt.Println(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"secret: synthetic host fixture denial"}}`)
	case "exit1":
		os.Exit(1)
	case "fatal":
		// An actual post-exec Go runtime fatal error, not a simulated exit status.
		select {}
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		os.Exit(2)
	case "malformed":
		fmt.Println(`{not-json`)
	case "schema":
		fmt.Println(`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":42}}`)
	case "timeout":
		time.Sleep(8 * time.Second)
	case "go-hook", "bash-hook":
		args := []string{"hook", "claude"}
		if mode == "bash-hook" {
			args = nil
		}
		cmd := exec.Command(binary, args...)
		stdin, pipeErr := cmd.StdinPipe()
		if pipeErr != nil {
			os.Exit(2)
		}
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if cmd.Start() != nil {
			os.Exit(1)
		}
		_, _ = stdin.Write(data)
		_ = stdin.Close()
		if err := cmd.Wait(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() > 0 {
				os.Exit(exit.ExitCode())
			}
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}
