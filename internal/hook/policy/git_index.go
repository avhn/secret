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

func indexProtected(dir, home string) bool {
	if dir == "" {
		return true
	}
	data, err := boundedMetadata(filepath.Join(dir, "index"), maxIndexBytes)
	if os.IsNotExist(err) {
		// An initialized empty/bare repository may have no index yet.
		info, headErr := os.Stat(filepath.Join(dir, "HEAD"))
		return headErr != nil || !info.Mode().IsRegular()
	}
	return err != nil || indexNamesProtected(data, home)
}

// indexNamesProtected decodes v2/v3 padded and v4 prefix-compressed names.
// Unknown mandatory extensions (including split/sparse indexes), malformed
// records, unsupported object formats and budget exhaustion all fail closed.
func indexNamesProtected(data []byte, home string) bool {
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
		if paths.LexicalProtected(name, string(os.PathSeparator), home) {
			protected = true
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

// repositoryAlias reads only bounded, regular Git config metadata. Git aliases
// may execute shell code or expand to other subcommands; never run Git to look
// them up, since even config lookup may load untrusted configuration.
func repositoryAlias(dir, name string) (string, bool) {
	if dir == "" || strings.ContainsAny(name, "\r\n\x00") {
		return "", false
	}
	data, err := boundedMetadata(filepath.Join(dir, "config"), 64<<10)
	if err != nil {
		return "", false
	}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			continue
		}
		if section != "[alias]" || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), name) {
			return strings.TrimSpace(value), true
		}
	}
	return "", false
}
