//go:build windows

package hook

import "github.com/avhn/secret/internal/hook/input"

// Only the named Claude tool can reach the pending adapter. Codex has no
// evidenced PowerShell dialect or workdir contract. Production always denies.
func powershellDecision(host string, e input.Envelope, cwd, home string) string {
	if host != "claude" || e.Tool != "PowerShell" || powershellClassifier == nil {
		return powershellReason
	}
	return powershellClassifier(e, cwd, home)
}

// Unknown command-bearing tools are unknown shell contracts, not Bash or
// PowerShell source. Named shell dialects also deny when command is absent.
func unknownShellDecision(e input.Envelope) string {
	if _, present := e.Fields["command"]; present {
		return windowsShellReason
	}
	switch e.Tool {
	case "Shell", "shell", "CMD", "Cmd", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "exec_command", "shell_command":
		return windowsShellReason
	}
	return ""
}
