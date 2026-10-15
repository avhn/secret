package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Yarn's user configuration may contain npmAuthToken; project configuration
// remains readable. Match both lexical intent and physical aliases to HOME.
func homeCredential(name, home string) bool {
	if home == "" || !strings.EqualFold(filepath.Base(name), ".yarnrc.yml") {
		return false
	}
	for _, root := range []string{home, physicalOrClean(home)} {
		if sameCredentialPath(filepath.Clean(name), filepath.Join(root, ".yarnrc.yml")) {
			return true
		}
	}
	return false
}

func physicalOrClean(name string) string {
	if resolved, err := physical(name); err == nil {
		return resolved
	}
	return filepath.Clean(name)
}

// ConfiguredProtected recognizes literal KUBECONFIG path lists, including
// physical aliases. Values are path metadata only, never opened or evaluated.
func ConfiguredProtected(name, cwd, workdir, home, config string) bool {
	if config == "" {
		return false
	}
	candidate := StreamBase(unresolved(name, cwd, workdir, home))
	for _, entry := range filepath.SplitList(config) {
		if entry == "" {
			continue
		}
		target := unresolved(entry, cwd, "", home)
		if sameCredentialPath(filepath.Clean(candidate), filepath.Clean(target)) || sameCredentialPath(physicalOrClean(candidate), physicalOrClean(target)) {
			return true
		}
	}
	return false
}

// ConfiguredTreeProtected conservatively checks whether a search root contains
// any configured path, including a missing file that may be created later.
func ConfiguredTreeProtected(root, cwd, home, config string) bool {
	root = physicalOrClean(unresolved(root, cwd, "", home))
	for _, entry := range filepath.SplitList(config) {
		if entry == "" {
			continue
		}
		target := physicalOrClean(unresolved(entry, cwd, "", home))
		relative, err := filepath.Rel(root, target)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func sameCredentialPath(a, b string) bool {
	return a == b || runtime.GOOS == "windows" && strings.EqualFold(a, b)
}
