package policy

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
)

const maxIndexBytes = 16 << 20
const maxIndexEntries = 100000

// boundedMetadata reads only a regular, size-bounded repository metadata file.
// Object files are never opened by the analyzer.
func boundedMetadata(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, os.ErrInvalid
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() > limit {
		return nil, os.ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(data)) > limit {
		return nil, os.ErrInvalid
	}
	return data, err
}

// gitDirectory resolves a worktree gitfile without interpreting config or objects.
func gitDirectory(name string) string {
	info, err := os.Stat(name)
	if err != nil {
		return ""
	}
	if info.IsDir() {
		return name
	}
	data, err := boundedMetadata(name, 4096)
	if err != nil || !bytes.HasPrefix(data, []byte("gitdir: ")) {
		return ""
	}
	target := strings.TrimSpace(string(data[8:]))
	if target == "" || strings.ContainsAny(target, "\x00\r\n") {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(name), target)
	}
	if info, err = os.Stat(target); err != nil || !info.IsDir() {
		return ""
	}
	return target
}

func resolveGitDirectory(cwd, explicit string) string {
	if explicit != "" {
		return gitDirectory(explicit)
	}
	if !filepath.IsAbs(cwd) {
		return ""
	}
	physical, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return ""
	}
	for dir, count := physical, 0; count < 128; dir, count = filepath.Dir(dir), count+1 {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return gitDirectory(filepath.Join(dir, ".git"))
		}
		// A bare repository has no worktree .git directory.
		if info, err := os.Stat(filepath.Join(dir, "objects")); err == nil && info.IsDir() {
			if info, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && info.Mode().IsRegular() {
				return dir
			}
		}
		if filepath.Dir(dir) == dir {
			return ""
		}
	}
	return ""
}

func indexProtected(dir, home string, checks ...func(string) bool) bool {
	if dir == "" {
		return true
	}
	if info, err := os.Stat(filepath.Join(dir, "objects")); err == nil && info.IsDir() {
		if head, err := os.Stat(filepath.Join(dir, "HEAD")); err == nil && head.Mode().IsRegular() && filepath.Base(dir) != ".git" {
			return true // Bare repository, including one with an index.
		}
	}
	data, err := boundedMetadata(filepath.Join(dir, "index"), maxIndexBytes)
	// History can read objects even when an index has never been written.
	// Missing or unreadable indexes cannot certify content-producing Git.
	return err != nil || indexNamesProtected(data, home, checks...)
}

// Configured paths are relative to the command cwd, whereas index names are
// relative to the worktree root. Keep both anchors and the current alternatives
// in this per-command check, never a repository-only cached decision.
func (a *analyzer) gitIndexProtected(dir, cwd, worktree string) bool {
	config := a.credentialConfig()
	if config == "" && len(a.credentialPaths()) == 0 && os.Getenv("AWS_CONFIG_FILE") == "" && os.Getenv("AWS_SHARED_CREDENTIALS_FILE") == "" {
		return indexProtected(dir, a.home)
	}
	root := ""
	if worktree != "" {
		root = a.gitPath(worktree, cwd)
	} else {
		target, err := os.Stat(dir)
		if err != nil {
			return true
		}
		for candidate, count := cwd, 0; candidate != "" && count < 128; candidate, count = filepath.Dir(candidate), count+1 {
			gitdir := gitDirectory(filepath.Join(candidate, ".git"))
			if info, err := os.Stat(gitdir); err == nil && os.SameFile(info, target) {
				root = candidate
				break
			}
			if filepath.Dir(candidate) == candidate {
				break
			}
		}
	}
	if root == "" {
		return true
	}
	return indexProtected(dir, a.home, func(name string) bool {
		target := filepath.Join(root, filepath.FromSlash(name))
		return paths.ConfiguredProtected(target, cwd, "", a.home, config, a.credentialPaths()...)
	})
}

// indexNamesProtected decodes v2/v3 padded and v4 prefix-compressed names.
// Unknown mandatory extensions (including split/sparse indexes), malformed
// records, unsupported object formats and budget exhaustion all fail closed.
var indexAnchor = filepath.Join(string(os.PathSeparator), "index")

func indexNamesProtected(data []byte, home string, checks ...func(string) bool) bool {
	if len(data) < 32 || len(data) > maxIndexBytes || string(data[:4]) != "DIRC" {
		return true
	}
	version := binary.BigEndian.Uint32(data[4:8])
	count := binary.BigEndian.Uint32(data[8:12])
	if version < 2 || version > 4 || count > maxIndexEntries {
		return true
	}
	end := len(data) - sha1.Size
	sum := sha1.Sum(data[:end])
	if !bytes.Equal(sum[:], data[end:]) {
		return true
	}
	pos, previous := 12, ""
	protected := false
	for n := uint32(0); n < count; n++ {
		start := pos
		if end-pos < 62 {
			return true
		}
		flags := binary.BigEndian.Uint16(data[pos+60 : pos+62])
		pos += 62
		if flags&0x4000 != 0 {
			if version == 2 || end-pos < 2 {
				return true
			}
			pos += 2
		}
		strip := 0
		if version == 4 {
			for j := 0; ; j++ {
				if pos >= end || j >= 5 {
					return true
				}
				b := data[pos]
				pos++
				strip = (strip << 7) + int(b&127)
				if strip > len(previous) {
					return true
				}
				if b&128 == 0 {
					break
				}
				strip++
			}
		}
		nul := bytes.IndexByte(data[pos:end], 0)
		if nul < 0 || nul > 4096 {
			return true
		}
		name := previous[:len(previous)-strip] + string(data[pos:pos+nul])
		if version != 4 {
			name = string(data[pos : pos+nul])
		}
		if name == "" || len(name) > 4096 || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
			return true
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." || part == "." || part == "" {
				return true
			}
		}
		if int(flags&0xfff) != len(name) && flags&0xfff != 0xfff {
			return true
		}
		pos += nul + 1
		if version != 4 {
			padding := (8 - (pos-start)%8) % 8
			if end-pos < padding {
				return true
			}
			for _, b := range data[pos : pos+padding] {
				if b != 0 {
					return true
				}
			}
			pos += padding
		}
		// Anchor names independently of the host cwd; this is lexical index data.
		// A bare separator root would join to a Windows UNC prefix and lose the name.
		if paths.LexicalProtected(name, indexAnchor, home) {
			protected = true
		}
		for _, check := range checks {
			if check(name) {
				protected = true
			}
		}
		previous = name
	}
	for pos < end {
		if end-pos < 8 || data[pos] < 'A' || data[pos] > 'Z' {
			return true
		}
		size := uint64(binary.BigEndian.Uint32(data[pos+4 : pos+8]))
		pos += 8
		if size > uint64(end-pos) {
			return true
		}
		pos += int(size)
	}
	return protected
}
