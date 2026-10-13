package cli

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/avhn/secret/internal/backend"
	"github.com/avhn/secret/internal/store"
)

var launchKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type launchOptions struct {
	files, required, optional, args []string
	selectors                       store.Selectors
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
		case "-f", "--key", "--optional-key", "--env", "--label":
			if len(args) < 2 {
				return o, errOptionArgument
			}
			value = args[1]
			args = args[2:]
		default:
			if strings.HasPrefix(option, "--env=") || strings.HasPrefix(option, "--label=") {
				option, value, _ = strings.Cut(option, "=")
				args = args[1:]
			} else {
				return o, errors.New("expected -f, --key, --optional-key, --env, --label, or --")
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
	remove := map[string]bool{"SECRET_CHILD_DATA": true, "SECRET_CHILD_UNSET": true}
	for _, k := range selection.Keys {
		remove[k] = true
	}
	for _, k := range optional {
		remove[k] = true
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
		k, _, ok := strings.Cut(entry, "=")
		if ok && !remove[k] {
			result = append(result, entry)
		}
	}
	for _, k := range selection.Keys {
		if chosen[k] {
			result = append(result, k+"="+string(selection.Matched[k].Value))
			delete(chosen, k)
		}
	}
	return result, nil
}

func (c command) prepareLaunch(o launchOptions) (env []string, all [][]byte, err error) {
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
		if providerRef(ref) {
			records, e := backend.ListNames(c.dir, ref)
			if e != nil {
				return nil, nil, e
			}
			p, _, service, e := backend.Dispatch(ref)
			if e != nil {
				return nil, nil, e
			}
			// Read every registered record before selecting any export. A failed read
			// must never silently reduce the redaction set.
			parsed := make([]store.Record, 0, len(records))
			for _, r := range records {
				v, er := p.Get(service, r.Account)
				if er != nil {
					return nil, nil, errors.New("backend lookup failed")
				}
				owned = append(owned, v)
				parsed = append(parsed, store.Record{Key: r.Key, Value: v, Labels: r.Labels})
			}
			selected, e := store.Select(parsed, o.selectors)
			if e != nil {
				return nil, nil, e
			}
			selections = append(selections, selected)
		} else {
			path := strings.TrimPrefix(ref, "file:")
			info, e := os.Stat(path)
			if e != nil || !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("%s is missing or not a regular file", path)
			}
			data, e := os.ReadFile(path)
			if e != nil {
				return nil, nil, errors.New("cannot open store")
			}
			parsed, warnings := store.Parse(data)
			for _, w := range warnings {
				fmt.Fprint(c.errOut, w.Text)
			}
			selected, er := store.Select(parsed, o.selectors)
			if er != nil {
				clearRecords(parsed)
				clear(data)
				return nil, nil, er
			}
			// Parser owns copies of every value; source bytes can be cleared now.
			clear(data)
			selections = append(selections, selected)
		}
	}
	selection := store.Merge(selections...)
	env, err = childEnvironment(os.Environ(), selection, o.required, o.optional, c.loc.SecretsEnv)
	if err != nil {
		return nil, nil, err
	}
	return env, selection.AllValues, nil
}

func (c command) launch(mode string, args []string) int {
	o, e := parseLaunch(args, c.loc)
	if e != nil {
		if errors.Is(e, errOptionArgument) {
			return c.fail(e.Error(), 1)
		}
		return c.failure(e)
	}
	if launchUnsupported() {
		return c.fail("run and exec are unsupported on Windows before M5a", 1)
	}
	env, values, e := c.prepareLaunch(o)
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
	return c.runChild(o.args, env, values)
}
