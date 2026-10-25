//go:build windows

package paths

import (
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

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
	return samePathIdentity(a, b, nativeStat, invalidWindowsOperand)
}

// A share or drive can expose a home credential directory under a public name.
// Preserve those directory roles by identity, not just GetFinalPath's DOS/UNC
// spelling. Inspect names and attributes only, never credential file contents.
func nativeProtected(name, home string) bool {
	resolved, err := nativePhysical(name)
	if err != nil || lexical(resolved) || fileHomeCredential(resolved, home) {
		return true
	}
	// Directory roles apply outside HOME too, including a share that hides the
	// entire store-directory basename. Public files inside .aws/.ssh stay public.
	if nativeStoreDirectory(resolved) && !strings.EqualFold(filepath.Clean(name), resolved) {
		return true
	}
	type witness struct {
		name string
		info os.FileInfo
	}
	var roots []witness
	for _, suffix := range []string{".", ".secrets", ".aws", ".ssh", ".kube", ".docker", ".config", ".config/gh", ".config/gcloud", ".terraform.d", ".cargo"} {
		root := filepath.Join(home, filepath.FromSlash(suffix))
		if info, err := nativeStat(root); err == nil && info.IsDir() {
			roots = append(roots, witness{root, info})
		} else if err != nil && !os.IsNotExist(err) {
			return true
		}
	}
	tail := ""
	for candidate, count := resolved, 0; count < 128; count++ {
		info, err := nativeStat(candidate)
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
					witness := filepath.Join(root.name, tail)
					if lexical(witness) || fileHomeCredential(witness, home) {
						return true
					}
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
	if sameNativePath(name, filepath.Join(home, ".gitconfig")) || global != "" && sameNativePath(name, FileResolve(global, cwd, "", home)) {
		return true
	}
	roots := []string{filepath.Join(home, ".config", "git")}
	if xdg != "" {
		roots = append(roots, filepath.Join(xdg, "git"))
	}
	for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR"} {
		if value := os.Getenv(key); value != "" {
			roots = append(roots, FileResolve(value, cwd, "", home))
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
	file, err := openNativeMetadata(name)
	if err != nil {
		return name, err
	}
	defer file.Close()
	resolved, err := secure.FinalPath(file)
	if err != nil {
		return name, err
	}
	resolved = nativeDOSPath(resolved)
	local, err := localUNCPath(resolved)
	if err != nil {
		return name, fs.ErrPermission
	}
	if local != resolved {
		// Share metadata is only a candidate mapping. Certify it against the
		// opened UNC object using file ID and volume serial before trusting it.
		other, err := openNativeMetadata(local)
		if err != nil {
			return name, fs.ErrPermission
		}
		defer other.Close()
		left, leftErr := file.Stat()
		right, rightErr := other.Stat()
		if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
			return name, fs.ErrPermission
		}
		resolved, err = secure.FinalPath(other)
		if err != nil {
			return name, fs.ErrPermission
		}
		resolved = nativeDOSPath(resolved)
		// Do not recurse through another share or lose a protected lexical
		// witness in the local share path when a reparse target hides it.
		if strings.HasPrefix(resolved, `\\`) || lexical(local) {
			return name, fs.ErrPermission
		}
	}
	if !ValidPath(resolved) || !filepath.IsAbs(resolved) {
		return name, fs.ErrPermission
	}
	return filepath.Clean(resolved), nil
}

// nativeStat eagerly obtains identity from the same metadata-only handle.
// os.Stat may defer identity lookup until SameFile, which cannot report errors.
func nativeStat(name string) (os.FileInfo, error) {
	file, err := openNativeMetadata(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

func openNativeMetadata(name string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, fs.ErrPermission
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		// GetFileAttributes observes the final reparse point even when following
		// it failed. Missing children are peeled until that point is reached.
		if attributes, attrErr := windows.GetFileAttributes(pointer); attrErr == nil && attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return nil, fs.ErrPermission
		}
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

// Only kernel-generated extended names are admitted by this conversion.
func nativeDOSPath(name string) string {
	if strings.HasPrefix(name, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(name, `\\?\UNC\`)
	}
	return strings.TrimPrefix(name, `\\?\`)
}

func nativeStoreDirectory(name string) bool {
	switch strings.ToLower(filepath.Base(name)) {
	case ".secrets", ".aws", ".ssh", ".kube", ".docker", ".config", ".terraform.d", ".cargo":
		return true
	case "gh", "gcloud":
		return strings.EqualFold(filepath.Base(filepath.Dir(name)), ".config")
	}
	return false
}

var nativeShareInfo = windows.NewLazySystemDLL("netapi32.dll").NewProc("NetShareGetInfo")

// localUNCPath resolves local SMB shares without assuming that GetFinalPath
// translates a redirector name into its on-disk DOS spelling. Unknown or
// inaccessible local shares are errors, never public-name evidence.
func localUNCPath(name string) (string, error) {
	volume := filepath.VolumeName(name)
	if !strings.HasPrefix(volume, `\\`) {
		return name, nil
	}
	parts := strings.Split(strings.TrimPrefix(volume, `\\`), `\`)
	if len(parts) != 2 {
		return name, fs.ErrInvalid
	}
	local, err := localNativeHost(parts[0])
	if err != nil || !local {
		return name, err
	}
	share, err := windows.UTF16PtrFromString(parts[1])
	if err != nil {
		return name, fs.ErrInvalid
	}
	if err := nativeShareInfo.Find(); err != nil {
		return name, fs.ErrPermission
	}
	var buffer *byte
	status, _, _ := nativeShareInfo.Call(
		0, uintptr(unsafe.Pointer(share)), 2, uintptr(unsafe.Pointer(&buffer)))
	runtime.KeepAlive(share)
	if buffer != nil {
		defer windows.NetApiBufferFree(buffer)
	}
	if status != 0 || buffer == nil {
		return name, fs.ErrPermission
	}
	info := (*struct {
		Name                              *uint16
		Type                              uint32
		Remark                            *uint16
		Permissions, MaxUses, CurrentUses uint32
		Path, Password                    *uint16
	})(unsafe.Pointer(buffer))
	root := windows.UTF16PtrToString(info.Path)
	if info.Type&0xff != 0 || !ValidPath(root) || !filepath.IsAbs(root) || strings.HasPrefix(root, `\\`) {
		return name, fs.ErrPermission
	}
	return filepath.Join(root, strings.TrimLeft(strings.TrimPrefix(name, volume), `\`)), nil
}

func localNativeHost(host string) (bool, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" {
		return true, nil
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip != nil && ip.IsLoopback() {
		return true, nil
	}
	for _, kind := range []uint32{windows.ComputerNameNetBIOS, windows.ComputerNameDnsHostname, windows.ComputerNameDnsFullyQualified} {
		buffer := make([]uint16, 256)
		n := uint32(len(buffer))
		if err := windows.GetComputerNameEx(kind, &buffer[0], &n); err != nil {
			return false, err
		}
		if strings.EqualFold(host, windows.UTF16ToString(buffer[:n])) {
			return true, nil
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false, err
	}
	ips := []net.IP{ip}
	if ip == nil {
		// Also recognize DNS aliases of this machine. Bound lookup and deny
		// uncertainty rather than treating a failed lookup as a remote host.
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		answers, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return false, err
		}
		if len(answers) == 0 {
			return false, fs.ErrInvalid
		}
		ips = nil
		for _, answer := range answers {
			ips = append(ips, answer.IP)
		}
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true, nil
		}
		for _, address := range addresses {
			local, _, err := net.ParseCIDR(address.String())
			if err != nil {
				return false, err
			}
			if ip.Equal(local) {
				return true, nil
			}
		}
	}
	return false, nil
}
