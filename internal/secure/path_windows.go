//go:build windows

package secure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

// UserHome honors an explicit HOME and otherwise uses native USERPROFILE lookup.
func UserHome() (string, error) {
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", ErrPrivateFile
	}
	return home, nil
}

// ValidateStorePath rejects ambiguous Win32 names before filesystem access. It
// does not clean paths: native traversal and conservative lexical witnesses are
// separate concerns. Drive-absolute, UNC and ordinary relative paths are valid.
func ValidateStorePath(name string) error {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00<>\"|?*") {
		return ErrPrivateFile
	}
	name = strings.ReplaceAll(name, "/", `\`)
	if strings.HasPrefix(name, `\\.\`) || strings.HasPrefix(name, `\\?\`) || strings.HasPrefix(name, `\??\`) {
		return ErrPrivateFile
	}
	volume := filepath.VolumeName(name)
	if volume != "" {
		if !filepath.IsAbs(name) {
			return ErrPrivateFile
		}
		if strings.HasPrefix(volume, `\\`) {
			parts := strings.Split(strings.TrimPrefix(volume, `\\`), `\`)
			if len(parts) != 2 || !validWindowsComponent(parts[0]) || !validWindowsComponent(parts[1]) {
				return ErrPrivateFile
			}
		} else if len(volume) != 2 || volume[1] != ':' || !((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) {
			return ErrPrivateFile
		}
	} else if strings.HasPrefix(name, `\`) {
		return ErrPrivateFile
	}
	for _, component := range strings.Split(name[len(volume):], `\`) {
		if component == "" || component == "." || component == ".." {
			continue
		}
		if !validWindowsComponent(component) {
			return ErrPrivateFile
		}
	}
	return nil
}

func validWindowsComponent(name string) bool {
	if name == "" || strings.ContainsAny(name, ":\x00<>\"|?*") || strings.HasSuffix(name, " ") || strings.HasSuffix(name, ".") || !filepath.IsLocal(name) {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	// Go's IsLocal follows the running Windows version, which can allow device
	// names with extensions. Store names reject those aliases on every version.
	base, _, _ := strings.Cut(name, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return false
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return false
		}
	}
	return true
}

// ExplicitStorePath recognizes both native separators without cleaning them.
func ExplicitStorePath(name string) bool {
	return strings.ContainsAny(name, `/\`) || filepath.IsAbs(name)
}

// FinalPath returns the identity name of an already opened handle. This is not a
// replacement for lexical witnesses or an authorization to reopen the path.
func FinalPath(file *os.File) (string, error) {
	if file == nil {
		return "", ErrPrivateFile
	}
	buffer := make([]uint16, 512)
	for len(buffer) <= 32768 {
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), 0)
		runtime.KeepAlive(file)
		if err != nil || n == 0 {
			return "", ErrPrivateFile
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		if n >= 32768 {
			break
		}
		buffer = make([]uint16, int(n)+1)
	}
	return "", ErrPrivateFile
}
