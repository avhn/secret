// Package cli implements inventory and human-only commands.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/store"
	"golang.org/x/term"
)

var Version = "dev"

type command struct {
	in          *os.File
	out, errOut io.Writer
	dir         string
	loc         store.Locator
}

func (c command) fail(message string, status int) int {
	fmt.Fprintln(c.errOut, "secret: "+message)
	return status
}
func (c command) failure(e error) int { return c.fail(e.Error(), 1) }
func isTerminal(w io.Writer) bool     { f, ok := w.(*os.File); return ok && term.IsTerminal(int(f.Fd())) }
func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
func clearRecords(records []store.Record) {
	for _, record := range records {
		clear(record.Value)
	}
}

// Main runs one invocation with explicit streams. Only the terminal handles are inspected.
func Main(args []string, in *os.File, out, errOut io.Writer) int {
	c := command{in: in, out: out, errOut: errOut}
	if len(args) == 0 {
		return c.fail("subcommand required; use secret help", 1)
	}
	sub := args[0]
	args = args[1:]
	if sub == "--clipboard-clear" {
		if len(args) != 1 {
			return 2
		}
		seconds, err := strconv.Atoi(args[0])
		if err != nil || seconds < 0 || int64(seconds) > int64((1<<63-1)/int64(time.Second)) {
			return 2
		}
		value, err := io.ReadAll(in)
		if err != nil {
			return 1
		}
		defer clear(value)
		time.Sleep(time.Duration(seconds) * time.Second)
		current, err := pasteClipboard()
		if err == nil && bytes.Equal(current, value) {
			_ = copyClipboard(nil)
		}
		clear(current)
		return 0
	}
	switch sub {
	case "help", "--help", "-h":
		fmt.Fprint(out, usage)
		return 0
	case "version":
		if len(args) != 0 {
			return c.fail("version takes no arguments", 1)
		}
		fmt.Fprintf(out, "secret %s (go)\n", Version)
		return 0
	case "get":
		if !isTerminal(out) {
			return c.fail("get is human-terminal-only; use show or run instead", 1)
		}
	case "list", "show", "stash", "clip", "run", "exec":
	default:
		return c.fail("unknown subcommand; use secret help", 1)
	}
	home := os.Getenv("HOME")
	dir := os.Getenv("SECRETS_DIR")
	if dir == "" {
		dir = filepath.Join(home, ".secrets")
	}
	env := os.Getenv("SECRETS_ENV")
	if env == "" {
		env = filepath.Join(home, ".secrets.env")
	}
	c.dir = dir
	c.loc = store.Locator{Home: home, SecretsDir: dir, SecretsEnv: env, IsFile: func(p string) bool { s, e := os.Stat(p); return e == nil && s.Mode().IsRegular() }, Glob: filepath.Glob}
	if sub == "run" || sub == "exec" {
		return c.launch(sub, args)
	}
	if sub == "list" {
		if len(args) != 0 {
			return c.fail("list takes no arguments", 1)
		}
		refs, e := c.defaults()
		if e != nil {
			return c.failure(e)
		}
		if len(refs) == 0 {
			fmt.Fprintln(errOut, "no secret stores found")
		}
		for _, r := range refs {
			fmt.Fprintln(out, r)
		}
		return 0
	}
	sel, rest, e := selectors(args)
	if e != nil {
		if errors.Is(e, errOptionArgument) {
			return c.fail(e.Error(), 1)
		}
		return c.failure(e)
	}
	switch sub {
	case "show":
		var refs []string
		if len(rest) == 0 {
			refs, e = c.defaults()
			if e != nil {
				return c.failure(e)
			}
		} else {
			for _, r := range rest {
				ref, er := c.loc.Resolve(r)
				if er != nil {
					return c.failure(er)
				}
				refs = append(refs, ref)
			}
		}
		if len(refs) == 0 {
			fmt.Fprintln(out, "no secret stores found")
		}
		for _, ref := range refs {
			lines, er := c.show(ref, sel)
			if er != nil {
				return c.failure(er)
			}
			fmt.Fprintln(out, ref)
			for _, line := range lines {
				fmt.Fprint(out, line)
			}
		}
	case "stash":
		if len(rest) != 2 {
			return c.fail("stash needs FILE KEY", 1)
		}
		if e = store.ValidateIdentity(rest[1], nil); e != nil {
			return c.fail("invalid key name", 1)
		}
		ref, er := c.loc.Resolve(rest[0])
		if er != nil {
			return c.failure(er)
		}
		value, er := c.input(rest[1])
		if er != nil {
			return c.failure(er)
		}
		defer clear(value)
		if providerRef(ref) {
			er = backend.Stash(dir, ref, rest[1], sel, value, nil)
		} else {
			er = store.StashWithSecretsDir(dir, strings.TrimPrefix(ref, "file:"), rest[1], sel, value)
		}
		if er != nil {
			return c.failure(er)
		}
		fmt.Fprintf(out, "stored %s in %s\n", rest[1], strings.TrimPrefix(ref, "file:"))
	case "get", "clip":
		if sub == "get" && len(rest) != 2 {
			return c.fail("get needs FILE KEY", 1)
		}
		if sub == "clip" && len(rest) != 2 && len(rest) != 3 {
			return c.fail("clip needs FILE KEY [SECONDS]", 1)
		}
		secs := 45
		if sub == "clip" && len(rest) == 3 {
			if rest[2] == "" {
				return c.fail("SECONDS must be a number", 1)
			}
			for _, b := range rest[2] {
				if b < '0' || b > '9' {
					return c.fail("SECONDS must be a number", 1)
				}
			}
			secs, e = strconv.Atoi(rest[2])
			if e != nil || int64(secs) > int64((1<<63-1)/int64(time.Second)) {
				return c.fail("SECONDS must be a number", 1)
			}
		}
		ref, er := c.loc.Resolve(rest[0])
		if er != nil {
			return c.failure(er)
		}
		value, er := c.lookup(ref, rest[1], sel)
		if er != nil {
			return c.failure(er)
		}
		defer clear(value)
		if sub == "get" {
			_, er = out.Write(value)
			if er == nil {
				_, er = out.Write([]byte{'\n'})
			}
			if er != nil {
				return c.fail("terminal write failed", 1)
			}
			return 0
		}
		if er = copyClipboard(value); er != nil {
			return c.failure(er)
		}
		if er = startClipboardClear(value, secs); er != nil {
			return c.failure(er)
		}
		fmt.Fprintf(out, "copied %s; clears in %ds if unchanged\n", rest[1], secs)
	}
	return 0
}

var errOptionArgument = errors.New("option needs an argument")

func selectors(args []string) (store.Selectors, []string, error) {
	s := store.Selectors{}
	i := 0
	for i < len(args) {
		arg := args[i]
		opt := arg
		value := ""
		if strings.HasPrefix(arg, "--env=") || strings.HasPrefix(arg, "--label=") {
			opt, value, _ = strings.Cut(arg, "=")
			i++
		} else if arg == "--env" || arg == "--label" {
			if i+1 >= len(args) {
				return nil, nil, errOptionArgument
			}
			value = args[i+1]
			i += 2
		} else {
			break
		}
		if e := s.AddSelector(opt, value); e != nil {
			return nil, nil, e
		}
	}
	return s, args[i:], nil
}
func providerRef(ref string) bool {
	return strings.HasPrefix(ref, "keychain:") || strings.HasPrefix(ref, "libsecret:")
}
func (c command) defaults() ([]string, error) {
	var refs []string
	keys, e := filepath.Glob(filepath.Join(c.dir, "*.keys"))
	if e != nil {
		return nil, e
	}
	for _, path := range keys {
		info, er := os.Lstat(path)
		if er != nil {
			return nil, errors.New("cannot read manifest")
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			return nil, errors.New("invalid or mismatched manifest")
		}
		data, er := os.ReadFile(path)
		if er != nil {
			return nil, errors.New("cannot read manifest")
		}
		backendName := ""
		if bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=keychain\n")) {
			backendName = "keychain"
		} else if bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=libsecret\n")) {
			backendName = "libsecret"
		} else {
			return nil, errors.New("invalid manifest backend")
		}
		ref := backendName + ":" + strings.TrimSuffix(filepath.Base(path), ".keys")
		if _, er = backend.ListNames(c.dir, ref); er != nil {
			return nil, er
		}
		refs = append(refs, ref)
	}
	files, e := c.loc.Defaults()
	if e != nil {
		return nil, e
	}
	return append(refs, files...), nil
}
func stored(key, label string) string {
	if label != "" {
		return fmt.Sprintf("  %s [%s]=<stored>\n", key, label)
	}
	return fmt.Sprintf("  %s=<stored>\n", key)
}
func selectManifest(records []store.ManifestRecord, key string, sel store.Selectors) (*store.ManifestRecord, error) {
	var match *store.ManifestRecord
	ambiguous := false
	for i := range records {
		r := &records[i]
		if r.Key != key {
			continue
		}
		qualifies := true
		for n, v := range r.Labels {
			if sel[n] != v {
				qualifies = false
				break
			}
		}
		if !qualifies {
			continue
		}
		if match == nil || len(match.Labels) < len(r.Labels) {
			match = r
			ambiguous = false
		} else if len(match.Labels) == len(r.Labels) {
			if store.CanonicalLabels(match.Labels) != store.CanonicalLabels(r.Labels) {
				ambiguous = true
			}
			match = r
		}
	}
	if ambiguous {
		return nil, fmt.Errorf("ambiguous labels for %s", key)
	}
	return match, nil
}
func (c command) show(ref string, sel store.Selectors) ([]string, error) {
	selected := len(sel) != 0
	if providerRef(ref) {
		records, e := backend.ListNames(c.dir, ref)
		if e != nil {
			return nil, e
		}
		var lines []string
		if !selected {
			for _, r := range records {
				lines = append(lines, stored(r.Key, store.CanonicalLabels(r.Labels)))
			}
			return lines, nil
		}
		seen := map[string]bool{}
		for _, r := range records {
			if seen[r.Key] {
				continue
			}
			seen[r.Key] = true
			match, er := selectManifest(records, r.Key, sel)
			if er != nil {
				return nil, er
			}
			if match == nil {
				lines = append(lines, "  "+r.Key+"=<unset>\n")
			} else {
				lines = append(lines, stored(r.Key, store.CanonicalLabels(match.Labels)))
			}
		}
		return lines, nil
	}
	path := strings.TrimPrefix(ref, "file:")
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is missing or not a regular file", path)
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, errors.New("cannot open store")
	}
	defer clear(data)
	records, warnings := store.Parse(data)
	defer clearRecords(records)
	for _, w := range warnings {
		fmt.Fprint(c.errOut, w.Text)
	}
	selection, e := store.Select(records, sel)
	if e != nil {
		return nil, e
	}
	return store.ShowLines(records, selected, selection), nil
}
func (c command) lookup(ref, key string, sel store.Selectors) ([]byte, error) {
	if providerRef(ref) {
		records, e := backend.ListNames(c.dir, ref)
		if e != nil {
			return nil, e
		}
		r, e := selectManifest(records, key, sel)
		if e != nil {
			return nil, e
		}
		if r == nil {
			return nil, errors.New("key is not set")
		}
		p, _, service, e := backend.Dispatch(ref)
		if e != nil {
			return nil, e
		}
		value, e := p.Get(service, r.Account)
		if e != nil {
			return nil, errors.New("backend lookup failed")
		}
		return value, nil
	}
	path := strings.TrimPrefix(ref, "file:")
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is missing or not a regular file", path)
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return nil, errors.New("cannot open store")
	}
	defer clear(data)
	records, warnings := store.Parse(data)
	defer clearRecords(records)
	for _, w := range warnings {
		fmt.Fprint(c.errOut, w.Text)
	}
	selection, e := store.Select(records, sel)
	if e != nil {
		return nil, e
	}
	r, ok := selection.Matched[key]
	if !ok {
		return nil, errors.New("key is not set")
	}
	return append([]byte(nil), r.Value...), nil
}
func (c command) input(key string) ([]byte, error) {
	if term.IsTerminal(int(c.in.Fd())) {
		fmt.Fprintf(c.errOut, "%s: ", key)
		value, e := term.ReadPassword(int(c.in.Fd()))
		fmt.Fprintln(c.errOut)
		if e != nil {
			return nil, errors.New("no input")
		}
		return value, nil
	}
	return io.ReadAll(c.in)
}

// startClipboardClear keeps the conditional clear alive after the caller exits.
// Only the timeout enters argv; the private value travels through a pipe.
func startClipboardClear(value []byte, seconds int) error {
	executable, err := os.Executable()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return errors.New("clipboard clear setup failed")
	}
	defer read.Close()
	cmd := exec.Command(executable, "--clipboard-clear", strconv.Itoa(seconds))
	cmd.Stdin = read
	if err = cmd.Start(); err != nil {
		write.Close()
		return errors.New("clipboard clear setup failed")
	}
	read.Close()
	_, err = write.Write(value)
	closeErr := write.Close()
	_ = cmd.Process.Release()
	if err != nil || closeErr != nil {
		return errors.New("clipboard clear setup failed")
	}
	return nil
}
func clipboardTool(copy bool) (*exec.Cmd, error) {
	names := []string{"pbcopy", "wl-copy", "xclip"}
	if !copy {
		names = []string{"pbpaste", "wl-paste", "xclip"}
	}
	for _, name := range names {
		path, e := exec.LookPath(name)
		if e != nil {
			continue
		}
		args := []string{}
		if name == "xclip" {
			args = []string{"-selection", "clipboard"}
			if !copy {
				args = append(args, "-o")
			}
		}
		if name == "wl-paste" {
			args = []string{"--no-newline"}
		}
		return exec.Command(path, args...), nil
	}
	return nil, errors.New("no clipboard tool (pbcopy, wl-copy, xclip)")
}
func copyClipboard(value []byte) error {
	cmd, e := clipboardTool(true)
	if e != nil {
		return e
	}
	cmd.Stdin = bytes.NewReader(value)
	if e = cmd.Run(); e != nil {
		return errors.New("clipboard copy failed")
	}
	return nil
}
func pasteClipboard() ([]byte, error) {
	cmd, e := clipboardTool(false)
	if e != nil {
		return nil, e
	}
	return cmd.Output()
}
