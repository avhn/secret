//go:build ignore

// fake-op is a synthetic executable, never an adapter to an installed op.
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "fake-pipe-holder" {
		time.Sleep(30 * time.Second)
		return
	}
	account := strings.Repeat("a", 26)
	reference := "op://" + strings.Repeat("v", 26) + "/" + strings.Repeat("i", 26) + "/"
	args := os.Args[1:]
	whoami := len(args) == 3 && args[0] == "whoami" && args[1] == "--format" && args[2] == "json"
	read := len(args) == 3 && args[0] == "read" && args[1] == "--no-newline" && (args[2] == reference+"password" || args[2] == reference+"other" || args[2] == reference+"missing")
	if !whoami && !read {
		os.Exit(90)
	}
	input, _ := io.ReadAll(io.LimitReader(os.Stdin, 1))
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	hasTTY := err == nil
	if tty != nil {
		tty.Close()
	}
	event := struct {
		Args []string `json:"args"`
		EOF  bool     `json:"eof"`
		TTY  bool     `json:"tty"`
	}{args, len(input) == 0, hasTTY}
	if log := os.Getenv("FAKE_OP_LOG"); log != "" {
		f, err := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			os.Exit(91)
		}
		json.NewEncoder(f).Encode(event)
		f.Close()
	}
	if os.Getenv("OP_SERVICE_ACCOUNT_TOKEN") != "synthetic-token" || os.Getenv("OP_BIOMETRIC_UNLOCK_ENABLED") != "false" || os.Getenv("OP_DEBUG") != "false" || os.Getenv("OP_CACHE") != "false" {
		os.Exit(92)
	}
	scenario := os.Getenv("FAKE_OP_SCENARIO")
	if whoami {
		switch scenario {
		case "wrong-account":
			account = strings.Repeat("b", 26)
		case "missing-account":
			io.WriteString(os.Stdout, "{}")
			return
		case "duplicate-account":
			io.WriteString(os.Stdout, `{"account_uuid":"`+account+`","account_uuid":"`+account+`"}`)
			return
		case "unauthenticated":
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(struct {
			Account string `json:"account_uuid"`
		}{account})
		return
	}
	switch scenario {
	case "stall":
		time.Sleep(30 * time.Second)
	case "stdout-cap":
		os.Stdout.Write(bytes.Repeat([]byte{'x'}, (1<<20)+1))
		return
	case "stderr-cap":
		os.Stderr.Write(bytes.Repeat([]byte{'x'}, (1<<20)+1))
		return
	case "partial-failure", "rate-limit", "revoked", "denied":
		io.WriteString(os.Stdout, "SYNTHETIC_REJECTED_VALUE")
		io.WriteString(os.Stderr, "SYNTHETIC_PROVIDER_DIAGNOSTIC")
		os.Exit(1)
	case "pipe-holder":
		cmd := exec.Command(os.Args[0], "fake-pipe-holder")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if cmd.Start() != nil {
			os.Exit(93)
		}
		return
	case "newline":
		os.Stdout.Write([]byte("synthetic-value\n"))
		return
	}
	if args[2] == reference+"missing" {
		os.Exit(1)
	}
	if args[2] == reference+"other" {
		os.Stdout.Write([]byte("synthetic-unselected"))
		return
	}
	os.Stdout.Write([]byte("synthetic-value"))
}
