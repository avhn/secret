//go:build windows

package paths

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// nativeGitProtected retains repository roles across share/drive aliases. Use
// eager handle identities: SameFile must not hide a deferred identity error.
func nativeGitProtected(name, cwd, workdir, home string) bool {
	var roots []os.FileInfo
	starts := []string{cwd}
	if workdir != "" {
		starts = append(starts, Resolve(".", cwd, workdir, home))
	}
	for _, start := range starts {
		if start == "" {
			continue
		}
		root, err := nativeRepositoryGitDir(start)
		if err != nil {
			return true
		}
		if root != "" {
			info, err := nativeStat(root)
			if err != nil || !info.IsDir() {
				return true
			}
			roots = append(roots, info)
		}
	}
	for candidate, count := filepath.Clean(name), 0; count < 128; count++ {
		info, err := nativeStat(candidate)
		if err != nil && !missingOperand(err) {
			return true
		}
		if err == nil {
			for _, root := range roots {
				if os.SameFile(info, root) {
					return true
				}
			}
			if info.IsDir() && nativeGitDirectory(candidate) {
				return true
			}
		}
		// Include the volume/share root itself before ending the walk. A bare
		// gitdir may be exposed as that root, without any .git path component.
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return false
		}
		candidate = parent
	}
	return true
}

func nativeRepositoryGitDir(start string) (string, error) {
	dir, err := nativePhysical(start)
	if err != nil {
		return "", err
	}
	for count := 0; count < 128; count++ {
		git := filepath.Join(dir, ".git")
		info, err := nativeStat(git)
		if err == nil {
			if info.IsDir() {
				return git, nil
			}
			if !info.Mode().IsRegular() || info.Size() > 4096 {
				return "", fs.ErrInvalid
			}
			file, err := os.Open(git)
			if err != nil {
				return "", err
			}
			data, readErr := io.ReadAll(io.LimitReader(file, 4097))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(data) > 4096 {
				return "", fs.ErrPermission
			}
			line := strings.TrimSpace(string(data))
			target, ok := strings.CutPrefix(line, "gitdir: ")
			if !ok || target == "" || strings.ContainsAny(target, "\r\n\x00") || !ValidPath(target) {
				return "", fs.ErrInvalid
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(dir, target)
			}
			return nativePhysical(target)
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		// A dangling .git reparse point is not an absent repository marker.
		if _, err := os.Lstat(git); err == nil || !os.IsNotExist(err) {
			return "", fs.ErrPermission
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
	return "", fs.ErrInvalid
}

func nativeGitDirectory(dir string) bool {
	// A signature requires an existing regular HEAD, like gitConfigTarget.
	// nativeStat intentionally turns a dangling reparse point into uncertainty
	// for protected-target lookup, but that is not evidence of a Git role.
	// Explicit repository/inherited roots above remain protected independently.
	head, err := os.Stat(filepath.Join(dir, "HEAD"))
	if err != nil {
		return !os.IsNotExist(err)
	}
	if !head.Mode().IsRegular() {
		return false
	}
	objects, objErr := nativeStat(filepath.Join(dir, "objects"))
	refs, refsErr := nativeStat(filepath.Join(dir, "refs"))
	if objErr != nil && !os.IsNotExist(objErr) || refsErr != nil && !os.IsNotExist(refsErr) {
		return true
	}
	if objErr == nil && refsErr == nil && objects.IsDir() && refs.IsDir() {
		return true
	}
	_, err = os.Lstat(filepath.Join(dir, "commondir"))
	return err == nil || !os.IsNotExist(err)
}
