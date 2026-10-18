package paths

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
	return physicalOrCleanWith(name, physical)
}

func physicalOrCleanWith(name string, resolve func(string) (string, error)) string {
	// Configured names remain witnesses even when a suffix is too long to
	// exist. Canonicalize its ancestor rather than losing a /var-style alias.
	// physical and canonicalExisting retain their stricter error behavior.
	resolved, err := canonicalPrefix(name, resolve, func(err error) bool {
		return missingOperand(err) || errors.Is(err, syscall.ENAMETOOLONG) ||
			runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(206)) // ERROR_FILENAME_EXCED_RANGE
	})
	if err == nil {
		return resolved
	}
	return filepath.Clean(name)
}

// configuredEntries combines Kubernetes path lists with the two singular AWS
// config paths. AWS paths are not split: a literal colon can be part of a name.
func configuredEntries(config string) []string {
	return append(filepath.SplitList(config), os.Getenv("AWS_CONFIG_FILE"), os.Getenv("AWS_SHARED_CREDENTIALS_FILE"))
}

// ConfiguredProtected recognizes literal configured credential paths, including
// physical aliases. Config is a Kubernetes path list; literals are whole singular
// AWS alternatives. Values are metadata only, never opened or evaluated.
func ConfiguredProtected(name, cwd, workdir, home, config string, literals ...string) bool {
	return configuredProtected(name, cwd, workdir, home, config, physicalOrClean, literals...)
}

func configuredProtected(name, cwd, workdir, home, config string, canonical func(string) string, literals ...string) bool {
	candidate := StreamBase(unresolved(name, cwd, workdir, home))
	for _, entry := range append(configuredEntries(config), literals...) {
		if entry == "" {
			continue
		}
		target := unresolved(entry, cwd, "", home)
		if sameCredentialPath(filepath.Clean(candidate), filepath.Clean(target)) || sameCredentialPath(canonical(candidate), canonical(target)) {
			return true
		}
	}
	return false
}

// ConfiguredTreeProtected conservatively checks whether a search root contains
// any configured path, including a missing file that may be created later.
func ConfiguredTreeProtected(root, cwd, home, config string, literals ...string) bool {
	root = physicalOrClean(unresolved(root, cwd, "", home))
	for _, entry := range append(configuredEntries(config), literals...) {
		if entry == "" {
			continue
		}
		target := physicalOrClean(unresolved(entry, cwd, "", home))
		// Match Bash's case-folded witnesses even on a case-sensitive host.
		relative, err := filepath.Rel(strings.ToLower(root), strings.ToLower(target))
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func sameCredentialPath(a, b string) bool {
	return strings.EqualFold(a, b)
}
