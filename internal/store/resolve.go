package store

import (
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var ErrInvalidKeystoreName = errors.New("invalid keystore name")
var backendName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// Locator injects environment and filesystem observations for pure resolution.
type Locator struct {
	Home, SecretsEnv, SecretsDir string
	IsFile                       func(string) bool
	Glob                         func(string) ([]string, error)
}

func (l Locator) envFile() string {
	if l.SecretsEnv != "" {
		return l.SecretsEnv
	}
	return filepath.Join(l.Home, ".secrets.env")
}
func (l Locator) dir() string {
	if l.SecretsDir != "" {
		return l.SecretsDir
	}
	return filepath.Join(l.Home, ".secrets")
}

// Resolve preserves explicit paths and validates provider references before use.
func (l Locator) Resolve(name string) (string, error) {
	if strings.HasPrefix(name, "wincred:") {
		// wincred stays inactive until Credential Manager dispatch is wired.
		return "", ErrInvalidKeystoreName
	}
	if ProviderReference(name) || strings.HasPrefix(name, "onepassword:") || strings.HasPrefix(name, "age:") {
		if !backendName.MatchString(name[strings.IndexByte(name, ':')+1:]) {
			return "", ErrInvalidKeystoreName
		}
		return name, nil
	}
	if strings.HasPrefix(name, "file:") {
		return name, nil
	}
	if strings.Contains(name, "/") || l.IsFile(name) {
		return name, nil
	}
	visible := filepath.Join(l.dir(), name+".secret")
	hidden := filepath.Join(l.dir(), "."+name+".secret")
	if l.IsFile(visible) || !l.IsFile(hidden) {
		return visible, nil
	}
	return hidden, nil
}

// Defaults lists file stores in Bash discovery order. Manifest discovery is
// deferred to the backend layer.
func (l Locator) Defaults() ([]string, error) {
	var files []string
	if l.IsFile(l.envFile()) {
		files = append(files, l.envFile())
	}
	for _, pattern := range []string{"*.secret", ".*.secret"} {
		names, err := l.Glob(filepath.Join(l.dir(), pattern))
		if err != nil {
			return nil, err
		}
		sort.Strings(names)
		for _, name := range names {
			if strings.HasSuffix(name, "~") || strings.HasSuffix(name, ".swp") || strings.HasSuffix(name, ".bak") {
				continue
			}
			if l.IsFile(name) {
				files = append(files, name)
			}
		}
	}
	return files, nil
}
