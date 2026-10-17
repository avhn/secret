package paths

import (
	"os"
	"path/filepath"
)

// Metadata retains name-resolution results for one bounded analysis only. It is
// not shared between envelopes or goroutines. Both successes and errors retain
// the existing fail-closed semantics; raw paths are keys so link/.. is not lost.
// This is a metadata snapshot, not a filesystem race or sandbox guarantee.
type Metadata struct {
	physical  map[string]pathResult
	canonical map[string]pathResult
	links     map[string]pathResult
	stats     map[string]statResult
}

type pathResult struct {
	name string
	err  error
}

type statResult struct {
	info os.FileInfo
	err  error
}

const maxMetadataEntries = 4096

func rememberPath(cache *map[string]pathResult, name string, resolve func(string) (string, error)) (string, error) {
	if result, ok := (*cache)[name]; ok {
		return result.name, result.err
	}
	value, err := resolve(name)
	if *cache == nil {
		*cache = make(map[string]pathResult)
	}
	if len(*cache) < maxMetadataEntries {
		(*cache)[name] = pathResult{value, err}
	}
	return value, err
}

func (m *Metadata) lstat(name string) (os.FileInfo, error) {
	if result, ok := m.stats[name]; ok {
		return result.info, result.err
	}
	info, err := os.Lstat(name)
	if m.stats == nil {
		m.stats = make(map[string]statResult)
	}
	if len(m.stats) < maxMetadataEntries {
		m.stats[name] = statResult{info, err}
	}
	return info, err
}

func (m *Metadata) resolve(name string) (string, error) {
	return rememberPath(&m.physical, name, func(name string) (string, error) {
		return physicalWith(name, m.lstat, func(name string) (string, error) {
			return rememberPath(&m.links, name, os.Readlink)
		}, func(name string) (string, error) {
			return rememberPath(&m.canonical, name, filepath.EvalSymlinks)
		})
	})
}

func (m *Metadata) physicalOrClean(name string) string {
	return physicalOrCleanWith(name, m.resolve)
}

// ConfiguredProtected uses the same configured-path proof with cached metadata.
func (m *Metadata) ConfiguredProtected(name, cwd, workdir, home, config string, literals ...string) bool {
	return configuredProtected(name, cwd, workdir, home, config, m.physicalOrClean, literals...)
}

func (m *Metadata) homeCredential(name, home string) bool {
	if home == "" || !sameCredentialPath(filepath.Base(name), ".yarnrc.yml") {
		return false
	}
	return sameCredentialPath(filepath.Clean(name), filepath.Join(home, ".yarnrc.yml")) || sameCredentialPath(filepath.Clean(name), filepath.Join(m.physicalOrClean(home), ".yarnrc.yml"))
}

// LexicalProtected retains configured and HOME aliases as lexical witnesses.
func (m *Metadata) LexicalProtected(name, cwd, home string) bool {
	raw := filepath.Clean(unresolved(name, cwd, "", home))
	return lexical(raw) || m.homeCredential(raw, home) || m.ConfiguredProtected(name, cwd, "", home, os.Getenv("KUBECONFIG"))
}

// Protected checks physical paths without changing ordinary metadata errors.
func (m *Metadata) Protected(name, cwd, workdir, home string) bool {
	raw := StreamBase(unresolved(name, cwd, workdir, home))
	if raw == "/proc/self/status" {
		return false
	}
	if lexical(filepath.Clean(raw)) || m.homeCredential(raw, home) || m.ConfiguredProtected(name, cwd, workdir, home, os.Getenv("KUBECONFIG")) {
		return true
	}
	resolved, err := m.resolve(raw)
	return err != nil || lexical(resolved) || m.homeCredential(resolved, home)
}
