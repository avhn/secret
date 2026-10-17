package input

import (
	"io"
	"time"
)

// ReadTimeout matches the retained Bash guard's envelope read alarm. The read
// must finish, including EOF, before analysis can certify an envelope.
const ReadTimeout = 2 * time.Second

// Read bounds both bytes and elapsed time for the initial host-envelope read.
// The buffered result prevents a late reader from blocking or writing a delayed
// decision. An arbitrary io.Reader cannot be cancelled: its owner must close it
// to release a pending read. The CLI exits after its single hook decision.
func Read(r io.Reader) ([]byte, error) {
	return readWithin(r, ReadTimeout)
}

func readWithin(r io.Reader, timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	go func() {
		read := result{err: ErrInvalid}
		defer func() {
			if recover() != nil {
				read = result{err: ErrInvalid}
			}
			done <- read
		}()
		read.data, read.err = io.ReadAll(io.LimitReader(r, MaxBytes+1))
	}()
	select {
	case read := <-done:
		if read.err != nil || len(read.data) > MaxBytes {
			return nil, ErrInvalid
		}
		return read.data, nil
	case <-timer.C:
		return nil, ErrInvalid
	}
}
