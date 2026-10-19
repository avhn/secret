package feature

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/avhn/secret/internal/secure"
)

// MaxTemplateBytes bounds template input. Rendered payloads are separately bounded
// to 16 MiB, including literal text and repeated substitutions.
const MaxTemplateBytes = 1 << 20
const maxRenderedBytes = 16 << 20

var (
	ErrTemplate        = errors.New("invalid template or unselected template key")
	ErrTemplatePath    = errors.New("unsafe private template namespace")
	ErrTemplateWrite   = errors.New("private template creation failed")
	ErrTemplateCleanup = errors.New("private template cleanup failed")
)

type templateDirectory struct {
	parent  *os.Root
	root    *os.Root
	name    string
	info    os.FileInfo
	private bool
}

// RenderedTemplate owns the anchored payload and directory handles. Call Close
// only after stopping the supervised process group. SIGKILL or power loss can
// leave protected plaintext behind; removal is not a secure-erasure guarantee.
// The path is for the child environment only, never diagnostics or child argv.
type RenderedTemplate struct {
	path    string
	dirs    []templateDirectory
	payload os.FileInfo
	closed  bool
}

// RenderTemplate borrows template and selected byte buffers without retaining
// them. Only exact {{KEY}} placeholders are supported, with no evaluation or
// recursive expansion. HOME is explicit; SECRETS_DIR never controls this path.
// Windows rejects before any filesystem access until private ACL support exists.
func RenderTemplate(home string, template []byte, selected map[string][]byte) (_ *RenderedTemplate, err error) {
	if runtime.GOOS == "windows" {
		return nil, secure.ErrUnsupported
	}
	data, err := renderTemplateBytes(template, selected)
	if err != nil {
		return nil, err
	}
	defer secure.Clear(data)
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == string(filepath.Separator) {
		return nil, ErrTemplatePath
	}
	parts := strings.Split(strings.TrimPrefix(home, string(filepath.Separator)), string(filepath.Separator))
	if len(parts) > 256 {
		return nil, ErrTemplatePath
	}
	base, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, ErrTemplatePath
	}
	r := &RenderedTemplate{}
	defer func() {
		if err != nil {
			if cleanupErr := r.Close(); cleanupErr != nil {
				err = cleanupErr
			}
		}
	}()
	// Retain each ancestor handle so validation detects path rebinding, not just
	// a symlink at the final namespace component. No ancestor is canonicalized.
	r.dirs = append(r.dirs, templateDirectory{root: base})
	for _, part := range parts {
		if err = r.openDirectory(part, false, false); err != nil {
			return nil, err
		}
	}
	for _, part := range []string{".secrets", ".rendered"} {
		if err = r.openDirectory(part, true, true); err != nil {
			return nil, err
		}
	}
	name := rand.Text()
	parent := r.dirs[len(r.dirs)-1].root
	if err = parent.Mkdir(name, 0700); err != nil {
		return nil, ErrTemplateWrite
	}
	if err = r.openDirectory(name, true, false); err != nil {
		_ = parent.Remove(name)
		return nil, err
	}
	r.path = filepath.Join(home, ".secrets", ".rendered", name, "payload")
	if err = r.validateDirectories(); err != nil {
		return nil, err
	}
	root := r.dirs[len(r.dirs)-1].root
	file, err := root.OpenFile("payload", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ErrTemplateWrite
	}
	// The exclusive file is owned even if a write or fsync fails.
	r.payload, err = file.Stat()
	if err == nil {
		err = file.Chmod(0600)
	}
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, ErrTemplateWrite
	}
	if err = r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

func renderTemplateBytes(template []byte, selected map[string][]byte) ([]byte, error) {
	if len(template) > MaxTemplateBytes {
		return nil, ErrTemplate
	}
	result := make([]byte, 0, len(template))
	appendBytes := func(value []byte) bool {
		if len(value) > maxRenderedBytes-len(result) {
			return false
		}
		// Clear obsolete allocations when growing a buffer containing values.
		if len(result)+len(value) > cap(result) {
			next := make([]byte, len(result), min(maxRenderedBytes, max(2*cap(result), len(result)+len(value))))
			copy(next, result)
			secure.Clear(result)
			result = next
		}
		result = append(result, value...)
		return true
	}
	for len(template) > 0 {
		start := bytes.Index(template, []byte("{{"))
		if start < 0 {
			if bytes.Contains(template, []byte("}}")) || !appendBytes(template) {
				secure.Clear(result)
				return nil, ErrTemplate
			}
			break
		}
		literal := template[:start]
		template = template[start+2:]
		end := bytes.Index(template, []byte("}}"))
		if end < 0 || bytes.Contains(literal, []byte("}}")) || !appendBytes(literal) {
			secure.Clear(result)
			return nil, ErrTemplate
		}
		key := template[:end]
		if !templateKey(key) {
			secure.Clear(result)
			return nil, ErrTemplate
		}
		value, ok := selected[string(key)] // Only a validated key name becomes a string.
		if !ok || !appendBytes(value) {
			secure.Clear(result)
			return nil, ErrTemplate
		}
		template = template[end+2:]
	}
	return result, nil
}

func templateKey(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	for i, b := range key {
		if b != '_' && !(b >= 'a' && b <= 'z') && !(b >= 'A' && b <= 'Z') && !(i > 0 && b >= '0' && b <= '9') {
			return false
		}
	}
	return true
}

func (r *RenderedTemplate) openDirectory(name string, private, create bool) error {
	parent := r.dirs[len(r.dirs)-1].root
	info, err := parent.Lstat(name)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = parent.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrTemplatePath
		}
		info, err = parent.Lstat(name)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || private && info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 && private {
		return ErrTemplatePath
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return ErrTemplatePath
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		root.Close()
		return ErrTemplatePath
	}
	r.dirs = append(r.dirs, templateDirectory{parent: parent, root: root, name: name, info: info, private: private})
	return nil
}

func (r *RenderedTemplate) validateDirectories() error {
	for _, dir := range r.dirs[1:] {
		info, err := dir.parent.Lstat(dir.name)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(dir.info, info) || dir.private && (info.Mode().Perm() != 0700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0) {
			return ErrTemplatePath
		}
	}
	return nil
}

// Path returns names-only metadata intended solely for SECRET_TEMPLATE_FILE.
func (r *RenderedTemplate) Path() string { return r.path }

// Validate rechecks all ancestor identities and private modes, plus the payload
// identity, immediately before launch. Anchored handles narrow filesystem races;
// they do not contain arbitrary same-user filesystem modifications.
func (r *RenderedTemplate) Validate() error {
	if r.closed || r.payload == nil {
		return ErrTemplatePath
	}
	if err := r.validateDirectories(); err != nil {
		return err
	}
	info, err := r.dirs[len(r.dirs)-1].root.Lstat("payload")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !os.SameFile(r.payload, info) {
		return ErrTemplatePath
	}
	return nil
}

// Close removes only the owned payload and random directory through anchored
// handles. Shared .secrets/.rendered directories and crash leftovers are retained.
func (r *RenderedTemplate) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	var err error
	if r.path != "" {
		dir := r.dirs[len(r.dirs)-1]
		if r.payload != nil {
			info, e := dir.root.Lstat("payload")
			if e != nil || !os.SameFile(r.payload, info) || dir.root.Remove("payload") != nil {
				err = ErrTemplateCleanup
			}
		}
		info, e := dir.parent.Lstat(dir.name)
		if e != nil || !os.SameFile(dir.info, info) || dir.parent.Remove(dir.name) != nil {
			err = ErrTemplateCleanup
		}
	}
	for i := len(r.dirs) - 1; i >= 0; i-- {
		if r.dirs[i].root.Close() != nil {
			err = ErrTemplateCleanup
		}
	}
	return err
}
