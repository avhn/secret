//go:build !windows

package cli

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strconv"
)

func clearClipboardIfUnchanged(value []byte) {
	current, err := pasteClipboard()
	if err == nil && bytes.Equal(current, value) {
		_ = copyClipboard(nil)
	}
	clear(current)
}

// startClipboardClear keeps the conditional clear alive after the caller exits.
// Only the timeout enters argv; the private value travels through a pipe.
func startClipboardClear(value []byte, seconds int) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	defer read.Close()
	cmd := exec.Command(executable, "--clipboard-clear", strconv.Itoa(seconds))
	cmd.Stdin = read
	if err = cmd.Start(); err != nil {
		write.Close()
		return errors.New("clipboard clear setup failed")
	}
	read.Close()
	_, err = write.Write(value)
	closeErr := write.Close()
	_ = cmd.Process.Release()
	if err != nil || closeErr != nil {
		return errors.New("clipboard clear setup failed")
	}
	return nil
}
func clipboardTool(copy bool) (*exec.Cmd, error) {
	names := []string{"pbcopy", "wl-copy", "xclip"}
	if !copy {
		names = []string{"pbpaste", "wl-paste", "xclip"}
	}
	for _, name := range names {
		path, e := exec.LookPath(name)
		if e != nil {
			continue
		}
		args := []string{}
		if name == "xclip" {
			args = []string{"-selection", "clipboard"}
			if !copy {
				args = append(args, "-o")
			}
		}
		if name == "wl-paste" {
			args = []string{"--no-newline"}
		}
		return exec.Command(path, args...), nil
	}
	return nil, errors.New("no clipboard tool (pbcopy, wl-copy, xclip)")
}
func copyClipboard(value []byte) error {
	cmd, e := clipboardTool(true)
	if e != nil {
		return e
	}
	cmd.Stdin = bytes.NewReader(value)
	if e = cmd.Run(); e != nil {
		return errors.New("clipboard copy failed")
	}
	return nil
}
func pasteClipboard() ([]byte, error) {
	cmd, e := clipboardTool(false)
	if e != nil {
		return nil, e
	}
	return cmd.Output()
}
