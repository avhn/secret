//go:build !windows

package backend

func newWincred() (Provider, error) { return nil, ErrUnsupported }
