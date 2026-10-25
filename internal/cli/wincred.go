package cli

import (
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/backend"
)

// wincredDefaults reads only dedicated names-only manifests. The existing *.keys
// pass and its order remain unchanged, including in mixed Bash/Go directories.
func (c command) wincredDefaults() ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(c.dir, "*.wincred-keys"))
	if err != nil {
		return nil, err
	}
	var refs []string
	for _, path := range paths {
		ref := "wincred:" + strings.TrimSuffix(filepath.Base(path), ".wincred-keys")
		if _, err := backend.ListNames(c.dir, ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	return refs, nil
}
