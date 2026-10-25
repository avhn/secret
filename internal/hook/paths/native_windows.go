//go:build windows

package paths

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/secure"
	"golang.org/x/sys/windows"
)

// Home honors HOME, falling back to native USERPROFILE discovery.
func Home() string {
	home, _ := secure.UserHome()
	return home
}

// ValidHome requires a native absolute home before home-specific classification.
func ValidHome(home string) bool { return filepath.IsAbs(home) && ValidPath(home) }

// ValidPath rejects Win32 ambiguity before anchoring or stripping stream names.
// Empty optional workdirs/search roots are handled by their existing callers.
func ValidPath(name string) bool {
	return name == "" || secure.ValidateStorePath(name) == nil
}

func nativeName(name string) string { return strings.ReplaceAll(name, `\`, "/") }

// Volume letters and UNC/mapped spellings need not have identical final names.
// Compare metadata identities, retaining equal missing suffixes conservatively.
func sameNativePath(a, b string) bool {
	for count := 0; count < 128; count++ {
		left, leftErr := os.Stat(a)
		right, rightErr := os.Stat(b)
		if leftErr == nil && rightErr == nil {
			return os.SameFile(left, right)
		}
		if !os.IsNotExist(leftErr) || !os.IsNotExist(rightErr) || !strings.EqualFold(filepath.Base(a), filepath.Base(b)) {
			return false
		}
		parentA, parentB := filepath.Dir(a), filepath.Dir(b)
		if parentA == a || parentB == b {
			return false
		}
		a, b = parentA, parentB
	}
	return false
}

// A share or drive can expose a home credential directory under a public name.
// Preserve those directory roles by identity, not just GetFinalPath's DOS/UNC
// spelling. Inspect names and attributes only, never credential file contents.
func nativeProtected(name, home string) bool {
	type witness struct {
		name string
		info os.FileInfo
	}
	var roots []witness
	for _, suffix := range []string{".", ".secrets", ".aws", ".ssh", ".kube", ".docker", ".config", ".config/gh", ".config/gcloud", ".terraform.d", ".cargo"} {
		root := filepath.Join(home, filepath.FromSlash(suffix))
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			roots = append(roots, witness{root, info})
		} else if err != nil && !os.IsNotExist(err) {
			return true
		}
	}
	tail := ""
	for candidate, count := filepath.Clean(name), 0; count < 128; count++ {
		info, err := os.Stat(candidate)
		if err != nil && !os.IsNotExist(err) {
			return true
		}
		if err == nil {
			for _, root := range roots {
				if os.SameFile(info, root.info) {
					// An aliased credential directory cannot borrow a public
					// root spelling to certify a search of its descendants.
					if tail == "" && root.name != home && !strings.EqualFold(filepath.Clean(name), root.name) {
						return true
					}
					resolved := filepath.Join(root.name, tail)
					return lexical(resolved) || homeCredential(resolved, home)
				}
			}
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return false
		}
		tail = filepath.Join(filepath.Base(candidate), tail)
		candidate = parent
	}
	return true
}

func nativeConfigProtected(name, cwd, home, xdg, global string) bool {
	if sameNativePath(name, filepath.Join(home, ".gitconfig")) || global != "" && sameNativePath(name, Resolve(global, cwd, "", home)) {
		return true
	}
	roots := []string{filepath.Join(home, ".config", "git")}
	if xdg != "" {
		roots = append(roots, filepath.Join(xdg, "git"))
	}
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR"} {
		if value := os.Getenv(key); value != "" {
			roots = append(roots, Resolve(value, cwd, "", home))
		}
	}
	for candidate, count := filepath.Clean(name), 0; count < 128; count++ {
		for _, root := range roots {
			if sameNativePath(candidate, root) {
				return true
			}
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return false
		}
		candidate = parent
	}
	return true
}

// nativePhysical follows native Win32 lexical cleaning, then obtains physical
// identity from a metadata-only handle. Resolve an existing prefix for a missing
// suffix, but never treat a dangling/unsupported reparse point as an absent file.
// This is a decision-time metadata witness, not a race-resistant authorization.
func nativePhysical(raw string) (string, error) {
	if !filepath.IsAbs(raw) {
		return raw, fs.ErrInvalid
	}
	return canonicalPrefix(filepath.Clean(raw), finalNativePath, missingOperand)
}

func finalNativePath(name string) (string, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return name, fs.ErrPermission
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		// GetFileAttributes observes the final reparse point even when following
		// it failed. Missing children are peeled until that point is reached.
		if attributes, attrErr := windows.GetFileAttributes(pointer); attrErr == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return name, fs.ErrPermission
		}
		return name, err
	}
	file := os.NewFile(uintptr(handle), name)
	defer file.Close()
	resolved, err := secure.FinalPath(file)
	if err != nil {
		return name, err
	}
	// FinalPath returns a kernel-generated extended DOS/UNC name. User-supplied
	// device namespaces are rejected above, never admitted by this conversion.
	if strings.HasPrefix(resolved, `\\?\UNC\`) {
		resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
	} else {
		resolved = strings.TrimPrefix(resolved, `\\?\`)
	}
	if !ValidPath(resolved) || !filepath.IsAbs(resolved) {
		return name, fs.ErrPermission
	}
	return filepath.Clean(resolved), nil
}
