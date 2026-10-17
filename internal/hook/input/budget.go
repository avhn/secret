package input

// MaxBytes caps the hook envelope before decoding.
const MaxBytes = (1 << 20) + (64 << 10)

// Structural bounds match the retained Bash envelope validator.
const (
	MaxKeys   = 4096
	MaxTokens = 32768
	MaxDepth  = 128
)

// MaxPathSeparators bounds path work before redundant components are cleaned.
const MaxPathSeparators = 4096
