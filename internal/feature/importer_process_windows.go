//go:build windows

package feature

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/transport"
)

// Importer values stay in bounded byte buffers. Native children share the same
// atomic Job enrollment as run/exec, even while operator entry points remain
// gated on the separate console and private-workflow prerequisites.
func runImporter(ctx context.Context, name string, args []string) (data []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if ctx.Err() != nil {
		return nil, secure.ErrTransaction
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return nil, secure.ErrTransaction
	}
	defer stdin.Close()
	stdout, outWrite, err := os.Pipe()
	if err != nil {
		return nil, secure.ErrTransaction
	}
	defer stdout.Close()
	defer outWrite.Close()
	stderr, errWrite, err := os.Pipe()
	if err != nil {
		return nil, secure.ErrTransaction
	}
	defer stderr.Close()
	defer errWrite.Close()
	process, err := transport.StartWindowsProcess(append([]string{name}, args...), os.Environ(), stdin, outWrite, errWrite)
	if err != nil {
		return nil, secure.ErrTransaction
	}
	outWrite.Close()
	errWrite.Close()
	defer func() {
		if process.Close() != nil {
			secure.Clear(data)
			data, err = nil, secure.ErrTransaction
		}
	}()
	output := &importerOutput{data: make([]byte, MaxImporterOutputBytes), cancel: cancel}
	diagnostic := &importerOutput{discard: true, cancel: cancel}
	defer func() {
		if err != nil {
			secure.Clear(output.data)
		}
	}()
	copies := make(chan error, 2)
	go func() { _, err := io.Copy(output, stdout); copies <- err }()
	go func() { _, err := io.Copy(diagnostic, stderr); copies <- err }()
	waited := make(chan int, 1)
	go func() {
		code, err := process.Wait()
		if err != nil {
			code = 1
		}
		waited <- code
	}()
	var drain <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	received, status, waitDone, failed := 0, 0, false, false
	canceled := ctx.Done()
	for received < 2 || !waitDone {
		select {
		case copyErr := <-copies:
			received++
			if copyErr != nil {
				failed = true
				cancel()
			}
		case status = <-waited:
			waitDone = true
			if received < 2 {
				timer = time.NewTimer(250 * time.Millisecond)
				drain = timer.C
			}
		case <-canceled:
			canceled = nil
			failed = true
			// Close below bounds native termination even if Wait cannot finish.
			waitDone = true
			process.Kill()
			stdout.Close()
			stderr.Close()
		case <-drain:
			drain = nil
			failed = true
			process.Kill()
			stdout.Close()
			stderr.Close()
		}
	}
	// Both copying goroutines have completed before their buffers are inspected
	// or cleared. No partial value or provider diagnostic escapes on any failure.
	if failed || status != 0 || output.failed || diagnostic.failed || ctx.Err() != nil {
		return nil, secure.ErrTransaction
	}
	return output.data[:output.count], nil
}
