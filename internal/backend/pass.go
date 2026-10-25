package backend

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

const passValueLimit = 64 << 10

// Diagnostics stay on the privately captured stderr pipe. --no-options prevents
// gpg.conf output/status directives from redirecting or contaminating plaintext.
const passGPGOptions = "--no-options --batch --no-tty --pinentry-mode error --status-fd 2 --logger-fd 2"

var passSigningKeys = regexp.MustCompile(`^[A-F0-9]{40}( [A-F0-9]{40})*$`)
var errPass = errors.New("pass provider operation failed")

type passRunner func(name string, args []string, input []byte, environment []string) ([]byte, []byte, error)

// passProvider snapshots configuration without accessing a store. Metadata paths
// never initialize it. Exact operations validate the root and pin the tool first.
// External direct pass writers and same-user path replacement are not contained.
type passProvider struct {
	directory   string
	environment []string
	executable  string
	searchPath  string
	run         passRunner
	once        sync.Once
	initErr     error
}

func newPass() (Provider, error) {
	if runtime.GOOS == "windows" {
		return nil, ErrUnsupported
	}
	home := os.Getenv("HOME")
	directory := os.Getenv("PASSWORD_STORE_DIR")
	if directory == "" {
		directory = filepath.Join(home, ".password-store")
	}
	if !filepath.IsAbs(home) || !filepath.IsAbs(directory) {
		return nil, errPass
	}
	directory = filepath.Clean(directory)
	var paths []string
	for _, entry := range filepath.SplitList(os.Getenv("PATH")) {
		if filepath.IsAbs(entry) {
			paths = append(paths, filepath.Clean(entry))
		}
	}
	searchPath := strings.Join(paths, string(os.PathListSeparator))
	// Enumerated contract: only these ambient variables survive. In particular,
	// BASH_ENV, SHELLOPTS, exported functions, GPG_TTY, PASSWORD_STORE_KEY, tracing,
	// extension directories and arbitrary GPG options are not inherited.
	environment := []string{"HOME=" + home, "PATH=" + searchPath, "LC_ALL=C", "PASSWORD_STORE_DIR=" + directory,
		"PASSWORD_STORE_UMASK=077", "PASSWORD_STORE_ENABLE_EXTENSIONS=false", "PASSWORD_STORE_GPG_OPTS=" + passGPGOptions}
	for _, key := range []string{"GNUPGHOME", "TMPDIR"} {
		if value := os.Getenv(key); value != "" {
			if !filepath.IsAbs(value) {
				return nil, errPass
			}
			environment = append(environment, key+"="+value)
		}
	}
	if key := os.Getenv("PASSWORD_STORE_SIGNING_KEY"); key != "" {
		if !passSigningKeys.MatchString(key) {
			return nil, errPass
		}
		environment = append(environment, "PASSWORD_STORE_SIGNING_KEY="+key)
	}
	return &passProvider{directory: directory, environment: environment, searchPath: searchPath, run: runProviderEnv}, nil
}

func (p *passProvider) call(args []string, input []byte) ([]byte, error) {
	out, diagnostic, err := p.run(p.executable, args, input, p.environment)
	defer secure.Clear(diagnostic)
	if err != nil {
		secure.Clear(out)
		return nil, errPass
	}
	return out, nil
}

func (p *passProvider) initialize() error {
	p.once.Do(func() {
		// Resolve only against the captured PATH, never a later ambient change.
		for _, directory := range filepath.SplitList(p.searchPath) {
			if !filepath.IsAbs(directory) {
				continue
			}
			candidate := filepath.Join(directory, "pass")
			info, err := os.Stat(candidate)
			if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				p.executable = candidate
				break
			}
		}
		if p.executable == "" {
			p.initErr = errPass
			return
		}
		out, err := p.call([]string{"version"}, nil)
		defer secure.Clear(out)
		// Match the version line, not an unanchored substring such as v1.7.40.
		valid := false
		for _, line := range bytes.Split(out, []byte{'\n'}) {
			if bytes.Equal(bytes.TrimSpace(line), []byte("=                  v1.7.4                  =")) {
				valid = true
			}
		}
		if err != nil || !valid {
			p.initErr = errPass
		}
	})
	return p.initErr
}

// openRoot rejects a final alias but permits platform aliases in the parent
// (/var on Darwin). All managed descendants are checked on the anchored handle.
func (p *passProvider) openRoot() (*os.Root, error) {
	if filepath.Clean(p.directory) != p.directory {
		return nil, errPass
	}
	info, err := os.Lstat(p.directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errPass
	}
	root, err := os.OpenRoot(p.directory)
	if err != nil {
		return nil, errPass
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) || p.regular(root, ".gpg-id") != nil {
		root.Close()
		return nil, errPass
	}
	return root, nil
}

func (p *passProvider) regular(root *os.Root, path string) error {
	info, err := root.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errPass
	}
	return nil
}

// parents verifies every managed directory and recipient-policy file. A missing
// parent is proof of absence only during the post-delete anchored check.
func (p *passProvider) parents(root *os.Root, service, account string, absentOK bool) (bool, error) {
	current := ""
	for _, component := range strings.Split(service+"/"+account, "/") {
		current = filepath.Join(current, component)
		info, err := root.Lstat(current)
		if os.IsNotExist(err) && absentOK {
			return true, nil
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return false, errPass
		}
		for _, policy := range []string{".gpg-id", ".gpg-id.sig"} {
			name := filepath.Join(current, policy)
			if _, err := root.Lstat(name); !os.IsNotExist(err) && p.regular(root, name) != nil {
				return false, errPass
			}
		}
	}
	return false, nil
}

func (p *passProvider) Get(service, account string) ([]byte, error) {
	if !validProviderPair(service, account) {
		return nil, errPass
	}
	root, err := p.openRoot()
	if err != nil {
		return nil, errPass
	}
	defer root.Close()
	if _, err := p.parents(root, service, account, false); err != nil {
		return nil, errPass
	}
	entry := service + "/" + account + "/value"
	if p.regular(root, entry+".gpg") != nil || p.initialize() != nil {
		return nil, errPass
	}
	out, err := p.call([]string{"show", "--", entry}, nil)
	defer secure.Clear(out)
	if err != nil || len(out) > passValueLimit {
		return nil, errPass
	}
	value, err := store.NormalizeValue(out)
	if err != nil || !bytes.Equal(value, out) {
		secure.Clear(value)
		return nil, errPass
	}
	return value, nil
}

func (p *passProvider) Put(service, account, label string, value []byte) error {
	if !validProviderPair(service, account) || len(value) > passValueLimit {
		return errPass
	}
	normalized, err := store.NormalizeValue(value)
	defer secure.Clear(normalized)
	if err != nil || !bytes.Equal(normalized, value) {
		return errPass
	}
	root, err := p.openRoot()
	if err != nil {
		return errPass
	}
	defer root.Close()
	if p.initialize() != nil {
		return errPass
	}
	// Validate/create service ancestors first. Reserve the account atomically;
	// pass 1.7.4's non-TTY yesno is NOT an overwrite guard.
	parts := strings.Split(service, "/")
	current := ""
	for _, component := range parts {
		current = filepath.Join(current, component)
		if err := root.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
			return errPass
		}
		info, err := root.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
			return errPass
		}
	}
	candidate := filepath.Join(service, account)
	if _, err := root.Lstat(candidate + ".gpg"); !os.IsNotExist(err) {
		return secure.ErrConflict
	}
	if err := root.Mkdir(candidate, 0700); err != nil {
		return secure.ErrConflict
	}
	if _, err := p.parents(root, service, account, false); err != nil {
		return errPass
	}
	// Root policy is also validated when signing is configured. pass itself must
	// verify the selected .gpg-id signature; never drop the configured signing key.
	if _, err := root.Lstat(".gpg-id.sig"); !os.IsNotExist(err) && p.regular(root, ".gpg-id.sig") != nil {
		return errPass
	}
	out, err := p.call([]string{"insert", "--multiline", "--", service + "/" + account + "/value"}, normalized)
	secure.Clear(out)
	return err
}

func (p *passProvider) Delete(service, account string) error {
	if !validProviderPair(service, account) {
		return errPass
	}
	root, err := p.openRoot()
	if err != nil {
		return errPass
	}
	defer root.Close()
	if _, err := p.parents(root, service, account, false); err != nil {
		return errPass
	}
	entry := service + "/" + account + "/value"
	if p.regular(root, entry+".gpg") != nil || p.initialize() != nil {
		return errPass
	}
	out, callErr := p.call([]string{"rm", "--force", "--", entry}, nil)
	secure.Clear(out)
	// cmd_delete ignores rm failure and the script unconditionally exits zero.
	// Prove absence even when the subprocess failed; uncertainty keeps recovery.
	absent, checkErr := p.parents(root, service, account, true)
	if checkErr != nil {
		return errPass
	}
	if !absent {
		if _, err := root.Lstat(entry + ".gpg"); !os.IsNotExist(err) {
			return errPass
		}
	}
	if callErr != nil {
		return errPass
	}
	return nil
}
