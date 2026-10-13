//go:build secretstub

package backend

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// directoryStub is available only in the separately tagged test executable.
// It never receives values in argv or diagnostic text.
type directoryStub struct {
	dir, backend string
}

func (s directoryStub) path(service, account string) string {
	return filepath.Join(s.dir, s.backend, service, account)
}
func (s directoryStub) log(op, service, account string) {
	f, err := os.OpenFile(filepath.Join(s.dir, "log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		_, _ = f.WriteString(op + " " + s.backend + ":" + strings.TrimPrefix(service, "secret/") + " " + account + "\n")
		_ = f.Close()
	}
}
func (s directoryStub) Get(service, account string) ([]byte, error) {
	s.log("get", service, account)
	if os.Getenv("SECRET_BACKEND_STUB_GET_FAIL") == "1" {
		return nil, errors.New("backend lookup failed")
	}
	info, err := os.Lstat(s.path(service, account))
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("backend lookup failed")
	}
	value, err := os.ReadFile(s.path(service, account))
	if err != nil {
		return nil, errors.New("backend lookup failed")
	}
	for _, b := range value {
		if b == '\n' || b == '\r' || b == 0 {
			return nil, errors.New("backend lookup failed")
		}
	}
	return value, nil
}
func (s directoryStub) Put(service, account, _ string, value []byte) error {
	s.log("put", service, account)
	if os.Getenv("SECRET_BACKEND_STUB_PUT_FAIL") == "1" {
		return errors.New("backend put failed")
	}
	path := s.path(service, account)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("backend put failed")
	}
	if err := os.WriteFile(path, value, 0600); err != nil {
		return errors.New("backend put failed")
	}
	return nil
}
func (s directoryStub) Delete(service, account string) error {
	return os.Remove(s.path(service, account))
}

func stubPublishFailure(p Provider) error {
	if _, ok := p.(directoryStub); ok && os.Getenv("SECRET_BACKEND_STUB_MANIFEST_FAIL") == "1" {
		return errors.New("manifest publish failed")
	}
	return nil
}

func testProvider(backend string) Provider {
	if dir := os.Getenv("SECRET_BACKEND_STUB_DIR"); filepath.IsAbs(dir) && dir != "" {
		return directoryStub{dir: dir, backend: backend}
	}
	return nil
}
