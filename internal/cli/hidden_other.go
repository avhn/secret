//go:build !linux && !darwin

package cli

// Other platforms keep term.ReadPassword's own echo handling; they are not
// release targets until their own gates pass.
func silenceEcho(int) (func() error, error) {
	return func() error { return nil }, nil
}
