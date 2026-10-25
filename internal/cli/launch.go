package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/feature"
	"github.com/avhn/secret/internal/secure"
	"github.com/avhn/secret/internal/store"
)

var launchKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Platform supervisors share filtering; Windows templates remain gated on private rendering.
// Keeping one channel from creation through cleanup avoids a pre-spawn signal gap.
type templateSupervisor interface {
	runTemplateChild(args, env []string, values [][]byte, signals <-chan os.Signal) int
}

type launchOptions struct {
	files, required, optional, args []string
	selectors                       store.Selectors
	templateFile                    string
}

func parseLaunch(args []string, loc store.Locator) (launchOptions, error) {
	o := launchOptions{selectors: store.Selectors{}}
	marker := false
	for len(args) > 0 {
		option := args[0]
		if option == "--" {
			marker = true
			o.args = args[1:]
			break
		}
		value := ""
		switch option {
		case "-f", "--key", "--optional-key", "--env", "--label", "--template-file":
			if len(args) < 2 {
				return o, errOptionArgument
			}
			value = args[1]
			args = args[2:]
		default:
			if strings.HasPrefix(option, "--env=") || strings.HasPrefix(option, "--label=") || strings.HasPrefix(option, "--template-file=") {
				option, value, _ = strings.Cut(option, "=")
				args = args[1:]
			} else {
				return o, errors.New("expected -f, --key, --optional-key, --env, --label, --template-file, or --")
			}
		}
		switch option {
		case "-f":
			ref, e := loc.Resolve(value)
			if e != nil {
				return o, e
			}
			o.files = append(o.files, ref)
		case "--key":
			o.required = append(o.required, value)
		case "--optional-key":
			o.optional = append(o.optional, value)
		case "--template-file":
			if value == "" || o.templateFile != "" {
				return o, feature.ErrTemplate
			}
			o.templateFile = value
		default:
			if e := o.selectors.AddSelector(option, value); e != nil {
				return o, e
			}
		}
	}
	if !marker || len(o.files) == 0 || len(o.args) == 0 {
		return o, errors.New("run/exec require -f FILE and -- CMD")
	}
	return o, nil
}

// childEnvironment removes every loaded name, including unselected records, from
// ambient. Explicit optional keys are removed even if no store defines them.
// Go's process APIs require string environment entries: those copies and GC
// visibility cannot be erased. Secret bytes never enter command arguments.
func childEnvironment(ambient []string, selection store.Selection, required, optional []string, envFile string) ([]string, error) {
	if err := validateEnvironmentSelection(selection); err != nil {
		return nil, err
	}
	remove := map[string]bool{"SECRET_CHILD_DATA": true, "SECRET_CHILD_UNSET": true}
	for _, k := range selection.Keys {
		remove[environmentKey(k)] = true
	}
	for _, k := range optional {
		remove[environmentKey(k)] = true
	}
	chosen := map[string]bool{}
	for _, k := range append(append([]string(nil), required...), optional...) {
		if !launchKey.MatchString(k) {
			return nil, errors.New("invalid selector name")
		}
	}
	if len(required)+len(optional) == 0 {
		for k := range selection.Matched {
			chosen[k] = true
		}
	} else {
		for _, k := range required {
			r, ok := selection.Matched[k]
			if !ok || len(r.Value) == 0 {
				return nil, fmt.Errorf("%s is missing or empty; stash it with: secret stash %s %s", k, envFile, k)
			}
			chosen[k] = true
		}
		for _, k := range optional {
			if _, ok := selection.Matched[k]; ok {
				chosen[k] = true
			}
		}
	}
	// Preserve the ambient order while replacing only store and optional names.
	result := make([]string, 0, len(ambient)+len(chosen))
	for _, entry := range ambient {
		k, ok := environmentEntryKey(entry)
		if ok && !remove[environmentKey(k)] {
			result = append(result, entry)
		}
	}
	for _, k := range selection.Keys {
		if chosen[k] {
			result = append(result, k+"="+string(selection.Matched[k].Value))
			delete(chosen, k)
		}
	}
	if err := validateChildEnvironment(result); err != nil {
		return nil, err
	}
	return result, nil
}

func (c command) prepareLaunch(o launchOptions) (env []string, all [][]byte, selected map[string][]byte, err error) {
	return c.prepareLaunchWith(o, nil)
}

// Explicit provider injection is for synthetic tests, never environment activation.
func (c command) prepareLaunchWith(o launchOptions, dispatch func(string) (backend.Provider, string, string, error)) (env []string, all [][]byte, selected map[string][]byte, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var selections []store.Selection
	var owned [][]byte
	defer func() {
		if err != nil {
			for _, v := range owned {
				clear(v)
			}
		}
		if err != nil {
			for _, s := range selections {
				for _, v := range s.AllValues {
					clear(v)
				}
			}
		}
	}()
	for _, ref := range o.files {
		if ageRef(ref) {
			if o.templateFile != "" {
				return nil, nil, nil, secure.ErrInvalidRequest
			}
			snapshot, e := c.ageConfig().Read(ref)
			if e != nil {
				return nil, nil, nil, e
			}
			selected, e := store.Select(snapshot.Records, o.selectors)
			if e != nil {
				snapshot.Close()
				return nil, nil, nil, e
			}
			// Selection borrows all independently owned record values. Transfer
			// them to launch cleanup after clearing the dotenv source buffer.
			secure.Clear(snapshot.Dotenv)
			selections = append(selections, selected)
		} else if providerRef(ref) {
			var records []store.ManifestRecord
			var p backend.Provider
			var service string
			var e error
			if dispatch == nil {
				records, p, service, e = c.openProviderRead(ctx, ref)
			} else {
				records, e = backend.ListNames(c.dir, ref)
				if e == nil {
					p, _, service, e = dispatch(ref)
				}
			}
			if e != nil {
				return nil, nil, nil, e
			}
			// Read every registered record before selecting any export. A failed read
			// must never silently reduce the redaction set.
			parsed := make([]store.Record, 0, len(records))
			for _, r := range records {
				v, er := p.Get(service, r.Account)
				if er != nil {
					clear(v)
					return nil, nil, nil, errors.New("backend lookup failed")
				}
				owned = append(owned, v)
				parsed = append(parsed, store.Record{Key: r.Key, Value: v, Labels: r.Labels})
			}
			selected, e := store.Select(parsed, o.selectors)
			if e != nil {
				return nil, nil, nil, e
			}
			selections = append(selections, selected)
		} else {
			path := strings.TrimPrefix(ref, "file:")
			info, e := os.Stat(path)
			if e != nil || !info.Mode().IsRegular() {
				return nil, nil, nil, fmt.Errorf("%s is missing or not a regular file", path)
			}
			data, e := store.ReadFile(path)
			if e != nil {
				return nil, nil, nil, errors.New("cannot open store")
			}
			if store.IsAgeStoreBytes(data) {
				secure.Clear(data)
				return nil, nil, nil, store.ErrAge
			}
			parsed, warnings := store.Parse(data)
			for _, w := range warnings {
				fmt.Fprint(c.errOut, w.Text)
			}
			selected, er := store.Select(parsed, o.selectors)
			if er != nil {
				clearRecords(parsed)
				clear(data)
				return nil, nil, nil, er
			}
			// Parser owns copies of every value; source bytes can be cleared now.
			clear(data)
			selections = append(selections, selected)
		}
	}
	selection := store.Merge(selections...)
	env, err = childEnvironment(os.Environ(), selection, o.required, o.optional, c.loc.SecretsEnv)
	if err != nil {
		return nil, nil, nil, err
	}
	selected = make(map[string][]byte)
	for key, record := range selection.Matched {
		if len(o.required)+len(o.optional) == 0 {
			selected[key] = record.Value
		}
	}
	for _, key := range append(append([]string(nil), o.required...), o.optional...) {
		if record, ok := selection.Matched[key]; ok {
			selected[key] = record.Value
		}
	}
	return env, selection.AllValues, selected, nil
}

func (c command) launch(mode string, args []string) (status int) {
	o, e := parseLaunch(args, c.loc)
	if e != nil {
		if errors.Is(e, errOptionArgument) {
			return c.fail(e.Error(), 1)
		}
		return c.failure(e)
	}
	if o.templateFile != "" && launchTemplateUnsupported() {
		return c.fail("templates are unsupported on Windows before native private rendering", 1)
	}
	if mode == "exec" && o.templateFile != "" {
		return c.fail("templates require supervised run", 1)
	}
	if o.templateFile != "" {
		for _, ref := range o.files {
			if ageRef(ref) {
				return c.failure(secure.ErrInvalidRequest)
			}
		}
	}
	env, values, selected, e := c.prepareLaunch(o)
	if e != nil {
		return c.failure(e)
	}
	defer func() {
		for _, v := range values {
			clear(v)
		}
	}()
	if mode == "exec" {
		for _, v := range values {
			clear(v)
		}
		return c.execChild(o.args, env)
	}
	if o.templateFile != "" {
		supervisor, ok := any(c).(templateSupervisor)
		if !ok {
			return c.fail("templates require a supported supervisor", 1)
		}
		signals := make(chan os.Signal, 4)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
		defer signal.Stop(signals)
		data, err := readLaunchTemplate(o.templateFile)
		if err != nil {
			return c.failure(err)
		}
		rendered, err := feature.RenderTemplate(c.loc.Home, data, selected)
		secure.Clear(data)
		if err != nil {
			return c.failure(err)
		}
		defer func() {
			if err := rendered.Close(); err != nil {
				status = c.failure(err)
			}
			select {
			case s := <-signals:
				if status == 0 {
					status = 128 + int(s.(syscall.Signal))
				}
			default:
			}
		}()
		// Neither ambient nor selected store values can override the dedicated
		// path. Contents never enter argv or this environment entry.
		filtered := make([]string, 0, len(env)+1)
		for _, entry := range env {
			if key, ok := environmentEntryKey(entry); ok && environmentKey(key) != environmentKey("SECRET_TEMPLATE_FILE") {
				filtered = append(filtered, entry)
			}
		}
		env = append(filtered, "SECRET_TEMPLATE_FILE="+rendered.Path())
		if err := rendered.Validate(); err != nil {
			if cleanupErr := rendered.Close(); cleanupErr != nil {
				return c.failure(cleanupErr)
			}
			return c.failure(err)
		}
		return supervisor.runTemplateChild(o.args, env, values, signals)
	}
	return c.runChild(o.args, env, values)
}

func readLaunchTemplate(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > feature.MaxTemplateBytes {
		return nil, feature.ErrTemplate
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, feature.ErrTemplate
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) || info.Size() > feature.MaxTemplateBytes {
		return nil, feature.ErrTemplate
	}
	data, err := io.ReadAll(io.LimitReader(file, feature.MaxTemplateBytes+1))
	if err != nil || len(data) > feature.MaxTemplateBytes {
		secure.Clear(data)
		return nil, feature.ErrTemplate
	}
	return data, nil
}
