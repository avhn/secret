//go:build !hooktrial

package input

// MaxBytes caps the deferred hook envelope before decoding.
const MaxBytes = 32 << 10
