package cli

import (
	"errors"
	"io"
	"time"

	"github.com/avhn/secret/internal/secure"
)

// Bound the pipe-fed helper without reallocating secret-bearing read buffers.
// This accommodates the existing 16 MiB age plaintext limit. Reject oversized
// values before copying on every platform, so no unserviceable timer is started.
const clipboardValueLimit = 16 << 20

type clipboardActions struct {
	copy             func([]byte) error
	startClear       func([]byte, int) error
	clearIfUnchanged func([]byte)
}

func (c clipboardActions) copyAndStartClear(value []byte, seconds int) error {
	if len(value) > clipboardValueLimit {
		return errors.New("clipboard clear setup failed")
	}
	if err := c.copy(value); err != nil {
		return err
	}
	if err := c.startClear(value, seconds); err != nil {
		c.clearIfUnchanged(value)
		return err
	}
	return nil
}

func runClipboardClear(in io.Reader, seconds int, clearIfUnchanged func([]byte)) int {
	// One extra byte distinguishes an exact-limit value from an oversized one.
	// ReadFull never grows this buffer, and its entire allocation is cleared on
	// success, short reads, read errors and oversized input alike.
	value := make([]byte, clipboardValueLimit+1)
	defer secure.Clear(value)
	n, err := io.ReadFull(in, value)
	if n > clipboardValueLimit || err != io.EOF && err != io.ErrUnexpectedEOF {
		return 1
	}
	time.Sleep(time.Duration(seconds) * time.Second)
	clearIfUnchanged(value[:n])
	return 0
}
