//go:build !windows

package cli

func templateFailureChild(_ string, _ string, args []string) []string { return args }
