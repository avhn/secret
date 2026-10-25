package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// FileResolve normalizes native file-tool spelling before anchoring. Bash policy
// must use Resolve: its operands can be inert source text rather than Win32 paths.
func FileResolve(name, cwd, workdir, home string) string {
	return Resolve(nativeName(name), cwd, workdir, home)
}

// FileProtected applies native validation and identity only to file/patch tools.
// The zero-value Metadata and Protected retain the pre-M5a Bash policy on Windows.
func FileProtected(name, cwd, workdir, home string) bool {
	if runtime.GOOS != "windows" {
		return Protected(name, cwd, workdir, home)
	}
	metadata := Metadata{fileTools: true}
	return metadata.Protected(name, cwd, workdir, home)
}

func fileProtected(name, cwd, workdir, home string, resolve func(string) (string, error)) bool {
	if !ValidPath(name) || !ValidPath(cwd) || !ValidPath(workdir) || !ValidHome(home) {
		return true
	}
	raw := FileResolve(name, cwd, workdir, home)
	if fileLexicalProtected(raw, cwd, home) {
		return true
	}
	resolved, err := resolve(raw)
	return err != nil || lexical(resolved) || fileHomeCredential(resolved, home) || NativeProtected(name, cwd, workdir, home)
}

// NativeProtected retains credential roles hidden by Windows volume/share aliases.
// Unix adapters retain their existing explicit-root and names-only rules.
func NativeProtected(name, cwd, workdir, home string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return FileConfiguredProtected(name, cwd, workdir, home, os.Getenv("KUBECONFIG")) || nativeProtected(FileResolve(name, cwd, workdir, home), home)
}

func fileHomeCredential(name, home string) bool {
	if home == "" || !strings.EqualFold(filepath.Base(name), ".yarnrc.yml") {
		return false
	}
	for _, root := range []string{home, physicalOrCleanWith(home, nativePhysical)} {
		target := filepath.Join(root, ".yarnrc.yml")
		if strings.EqualFold(filepath.Clean(name), target) || sameNativePath(name, target) {
			return true
		}
	}
	return false
}

func fileLexicalProtected(name, cwd, home string) bool {
	return lexical(filepath.Clean(name)) || fileHomeCredential(name, home) || FileConfiguredProtected(name, cwd, "", home, os.Getenv("KUBECONFIG"))
}

// FileLexicalProtected retains lexical witnesses for native names-only tools.
func FileLexicalProtected(name, cwd, home string) bool {
	if runtime.GOOS != "windows" {
		return LexicalProtected(name, cwd, home)
	}
	return fileLexicalProtected(FileResolve(name, cwd, "", home), cwd, home)
}

// FileConfiguredProtected includes native identities, never shell data operands.
func FileConfiguredProtected(name, cwd, workdir, home, config string, literals ...string) bool {
	if runtime.GOOS != "windows" {
		return ConfiguredProtected(name, cwd, workdir, home, config, literals...)
	}
	candidate := FileResolve(name, cwd, workdir, home)
	canonical := func(name string) string { return physicalOrCleanWith(name, nativePhysical) }
	same := func(a, b string) bool { return strings.EqualFold(a, b) || sameNativePath(a, b) }
	for _, entry := range append(configuredEntries(config), literals...) {
		if entry == "" {
			continue
		}
		target := FileResolve(entry, cwd, "", home)
		if same(filepath.Clean(candidate), filepath.Clean(target)) || same(canonical(candidate), canonical(target)) {
			return true
		}
	}
	return false
}

// FileConfigWriteProtected adds strict Win32 targets and native Git discovery at
// the file/patch boundary. ConfigWriteProtected remains the Bash policy proof.
func FileConfigWriteProtected(name, cwd, workdir, home, xdg, global string) bool {
	if runtime.GOOS != "windows" {
		return ConfigWriteProtected(name, cwd, workdir, home, xdg, global)
	}
	if !ValidPath(name) || !ValidPath(cwd) || !ValidPath(workdir) || !ValidPath(home) || !ValidPath(xdg) || !ValidPath(global) {
		return true
	}
	// Keep the component-walk proof: native final paths clean ".." lexically
	// and would drop a physical parent witness such as link/../root.
	if ConfigWriteProtected(name, cwd, workdir, home, xdg, global) {
		return true
	}
	name = nativeName(name)
	if strings.HasPrefix(name, "~") && !strings.HasPrefix(name, "~/") || cwd == "" && !filepath.IsAbs(name) {
		return true
	}
	raw := FileResolve(expandXDG(name, home, xdg), cwd, workdir, home)
	if inheritedGitRootTargetWith(raw, cwd, workdir, home, FileResolve, nativePhysical) {
		return true
	}
	target, err := nativePhysical(raw)
	return err != nil || nativeGitProtected(target, cwd, workdir, home) || gitConfigTarget(raw, cwd, home, xdg, global) || gitConfigTarget(target, cwd, home, xdg, global) || nativeConfigProtected(target, cwd, home, xdg, global)
}

// FileTreeProtectedScope scans native file-tool roots without changing shell scans.
func FileTreeProtectedScope(root, cwd, home string, includeIgnored bool) bool {
	if runtime.GOOS != "windows" {
		return TreeProtectedScope(root, cwd, home, includeIgnored)
	}
	return scanTreeWith(root, cwd, home, includeIgnored, filepath.WalkDir, time.Now, FileResolve, FileProtected)
}

// FileConfiguredTreeProtected retains configured witnesses in native tree scans.
func FileConfiguredTreeProtected(root, cwd, home, config string, literals ...string) bool {
	if runtime.GOOS != "windows" {
		return ConfiguredTreeProtected(root, cwd, home, config, literals...)
	}
	canonical := func(name string) string {
		return physicalOrCleanWith(FileResolve(name, cwd, "", home), nativePhysical)
	}
	root = canonical(root)
	for _, entry := range append(configuredEntries(config), literals...) {
		if entry == "" {
			continue
		}
		relative, err := filepath.Rel(strings.ToLower(root), strings.ToLower(canonical(entry)))
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
