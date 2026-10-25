// Package cli implements inventory and human-only commands.
package cli

import (
	"bytes"
	"context"
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
	"github.com/avhn/secret/internal/hook"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
	"golang.org/x/term"
)

var Version = "dev"

type command struct {
	in          *os.File
	out, errOut io.Writer
	ageIdentity string
	dir         string
	loc         store.Locator
	openRead    func(context.Context, string, string) ([]store.ManifestRecord, backend.Provider, string, error)
	// Explicit package-test injection only, never set by Main or the environment.
	onePasswordTest bool
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
	if sub == "hook" {
		if len(args) != 1 || (args[0] != "claude" && args[0] != "codex") {
			return c.fail("hook requires claude or codex", 1)
		}
		if err := hook.Decide(args[0], in, out); err != nil {
			return c.fail("hook output failed", 2)
		}
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
	case "list", "show", "stash", "clip", "run", "exec",
		"register", "age-init", "age-rekey", "import", "export", "rename", "rotate", "delete", "diff", "doctor", "completion", "audit", "mcp":
	default:
		return c.fail("unknown subcommand; use secret help", 1)
	}
	home, homeErr := secure.UserHome()
	if homeErr != nil && (os.Getenv("SECRETS_DIR") == "" || os.Getenv("SECRETS_ENV") == "") {
		return c.fail("cannot locate home directory", 1)
	}
	dir := os.Getenv("SECRETS_DIR")
	if dir == "" {
		dir = filepath.Join(home, ".secrets")
	}
	env := os.Getenv("SECRETS_ENV")
	if env == "" {
		env = filepath.Join(home, ".secrets.env")
	}
	if secure.ValidateStorePath(dir) != nil || secure.ValidateStorePath(env) != nil {
		return c.failure(store.ErrInvalidKeystoreName)
	}
	c.dir = dir
	c.loc = store.Locator{Home: home, SecretsDir: dir, SecretsEnv: env, IsFile: func(p string) bool { s, e := os.Stat(p); return e == nil && s.Mode().IsRegular() }, Glob: filepath.Glob}
	if sub == "age-init" || sub == "age-rekey" {
		return c.ageOperate(sub, args)
	}
	switch sub {
	case "stash", "get", "clip", "run", "exec":
		var err error
		args, c.ageIdentity, err = ageIdentityOption(args, home)
		if err != nil {
			return c.failure(err)
		}
	}
	if sub == "list" {
		for _, arg := range args {
			if arg == "--backend" || strings.HasPrefix(arg, "--backend=") {
				return c.ageList(args)
			}
		}
	}
	if status, handled := c.featureCommand(sub, args); handled {
		return status
	}
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
		if er = backend.ReadOnlyReference(ref); er != nil {
			return c.failure(er)
		}
		value, er := c.input(rest[1])
		if er != nil {
			return c.failure(er)
		}
		defer clear(value)
		if ageRef(ref) {
			er = (backend.AgeTransaction{Config: c.ageConfig(), Reference: ref}).Apply([]store.Mutation{{Kind: store.MutationPut, Key: rest[1], Labels: sel, Value: value}})
		} else if providerRef(ref) {
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
	return store.ProviderReference(ref) || strings.HasPrefix(ref, "onepassword:")
}
func (c command) defaults() ([]string, error) {
	var refs []string
	keys, e := filepath.Glob(filepath.Join(c.dir, "*.keys"))
	if e != nil {
		return nil, e
	}
	passKeys, e := filepath.Glob(filepath.Join(c.dir, "*.pass-keys"))
	if e != nil {
		return nil, e
	}
	keys = append(keys, passKeys...)
	for _, path := range keys {
		info, er := os.Lstat(path)
		if er != nil {
			return nil, errors.New("cannot read manifest")
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			return nil, errors.New("invalid or mismatched manifest")
		}
		data, er := store.ReadFile(path)
		if er != nil {
			return nil, errors.New("cannot read manifest")
		}
		backendName := ""
		suffix := ".keys"
		if bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=keychain\n")) {
			backendName = "keychain"
		} else if bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=libsecret\n")) {
			backendName = "libsecret"
		} else if strings.HasSuffix(path, ".pass-keys") && bytes.HasPrefix(data, []byte("secret-manifest-v1\nbackend=pass\n")) {
			backendName = "pass"
			suffix = ".pass-keys"
		} else {
			return nil, errors.New("invalid manifest backend")
		}
		ref := backendName + ":" + strings.TrimSuffix(filepath.Base(path), suffix)
		expected, er := store.ManifestPath(c.dir, ref)
		if er != nil || expected != path {
			return nil, errors.New("invalid manifest backend")
		}
		if _, er = backend.ListNames(c.dir, ref); er != nil {
			return nil, er
		}
		refs = append(refs, ref)
	}
	if backend.OnePasswordEnabled() || c.onePasswordTest {
		names, err := filepath.Glob(filepath.Join(c.dir, "*.onepassword-keys"))
		if err != nil {
			return nil, err
		}
		for _, path := range names {
			if _, err := store.ReadManifestV2(path, "onepassword"); err != nil {
				return nil, err
			}
			ref := "onepassword:" + strings.TrimSuffix(filepath.Base(path), ".onepassword-keys")
			if _, err := c.loc.Resolve(ref); err != nil {
				return nil, err
			}
			refs = append(refs, ref)
		}
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
	if providerRef(ref) || ageRef(ref) {
		var records []store.ManifestRecord
		var e error
		if ageRef(ref) {
			records, e = c.ageNames(ref)
		} else {
			records, e = backend.ListNames(c.dir, ref)
		}
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
	data, e := store.ReadFile(path)
	if e != nil {
		return nil, errors.New("cannot open store")
	}
	defer clear(data)
	if store.IsAgeStoreBytes(data) {
		return nil, store.ErrAge
	}
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
	if ageRef(ref) {
		snapshot, err := c.ageConfig().Read(ref)
		if err != nil {
			return nil, err
		}
		defer snapshot.Close()
		selection, err := store.Select(snapshot.Records, sel)
		if err != nil {
			return nil, err
		}
		record, ok := selection.Matched[key]
		if !ok {
			return nil, secure.ErrNotFound
		}
		return secure.Clone(record.Value), nil
	}

	if providerRef(ref) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		records, p, service, e := c.openProviderRead(ctx, ref)
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
		value, e := p.Get(service, r.Account)
		if e != nil {
			clear(value)
			return nil, errors.New("backend lookup failed")
		}
		return value, nil
	}
	path := strings.TrimPrefix(ref, "file:")
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is missing or not a regular file", path)
	}
	data, e := store.ReadFile(path)
	if e != nil {
		return nil, errors.New("cannot open store")
	}
	defer clear(data)
	if store.IsAgeStoreBytes(data) {
		return nil, store.ErrAge
	}
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
	if fd := int(c.in.Fd()); term.IsTerminal(fd) {
		// Echo goes off before the prompt appears, so typed-ahead bytes stay hidden.
		restore, e := silenceEcho(fd)
		if e != nil {
			return nil, errors.New("no input")
		}
		fmt.Fprintf(c.errOut, "%s: ", key)
		value, e := term.ReadPassword(fd)
		fmt.Fprintln(c.errOut)
		if r := restore(); e != nil || r != nil {
			secure.Clear(value)
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
