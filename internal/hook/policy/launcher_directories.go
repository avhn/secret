package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

const uvValueOptions = "--directory --project --python -p --with -w --with-editable --with-requirements " +
	"--extra --no-extra --group --no-group --only-group --package --index --default-index --index-url -i " +
	"--extra-index-url --find-links -f --config-file --cache-dir --python-preference --python-downloads " +
	"--resolution --prerelease --prerelease-package --fork-strategy --index-strategy --keyring-provider " +
	"--link-mode --config-setting -C --config-settings-package --env-file --color --allow-insecure-host " +
	"--refresh-package --upgrade-package -P --upgrade-group --exclude-newer --exclude-newer-package " +
	"--reinstall-package --no-binary-package --no-build-package --no-build-isolation-package --python-platform --from"

// uvRunChild consumes global, tool and run options before selecting the child.
// --directory changes the child cwd; --project selects metadata, not a cwd.
func (a *analyzer) uvRunChild(name string, args []string, depth int, cwd string, direct bool) bool {
	if a.configArgument(name, args, cwd) {
		return true
	}
	base, run, tool, module, help := cwd, name == "uvx", name == "uvx", false, false
	var inputs []struct{ key, value string }
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if !run && !tool && arg == "tool" {
			tool = true
			continue
		}
		if !run && arg == "run" {
			run = true
			continue
		}
		if arg == "--" && run {
			break
		}
		if !strings.HasPrefix(arg, "-") {
			if !run {
				return false
			}
			args = append([]string{arg}, args...)
			break
		}
		key, value, attached := strings.Cut(arg, "=")
		if !strings.HasPrefix(arg, "--") && len(arg) > 2 {
			key = arg[:2]
			if optionIn(uvValueOptions, key) {
				value, attached = strings.TrimPrefix(arg[2:], "="), true
			} else {
				// Boolean short options may precede a value-taking option.
				value, attached = "", false
				args = append([]string{"-" + arg[2:]}, args...)
			}
		}
		if optionIn(uvValueOptions, key) {
			if !attached {
				if len(args) == 0 {
					a.reason = roles.Indeterminate
					return true
				}
				value, args = args[0], args[1:]
			}
			if value == "" {
				a.reason = roles.Indeterminate
				return true
			}
			if key == "--directory" {
				cwd = a.resolve(value, base)
				value = cwd
			}
			if optionIn("--directory --project --config-file --with-requirements --env-file --cache-dir --with-editable --from --python -p --with -w", key) {
				inputs = append(inputs, struct{ key, value string }{key, value})
			}
			continue
		}
		if !attached && optionIn("--module -m", key) && run && !tool {
			module = true
			continue
		}
		if !attached && optionIn("--no-project --no-sync --no-env-file --isolated --locked --frozen --active --all-extras --no-dev --only-dev --all-groups --no-default-groups --no-editable --no-sources --no-config --offline --no-cache -n --quiet -q --verbose -v --native-tls --managed-python --no-managed-python --no-python-downloads --no-progress --compile-bytecode --help -h --version -V --script --no-install --upgrade -U --reinstall --force", key) {
			help = help || optionIn("--help -h --version -V", key)
			continue
		}
		a.reason = roles.Indeterminate
		return true
	}
	if !run {
		return false
	}
	// UV resolves source options after its global directory change, regardless
	// of option order. Keep those paths separate from the selected executable.
	for _, input := range inputs {
		if a.inputProtected(input.value, cwd) {
			a.reason = roles.FileInput
			return true
		}
		if optionIn("--directory --project --with-editable", input.key) {
			root := a.resolve(input.value, cwd)
			for _, file := range []string{"pyproject.toml", "uv.toml", "uv.lock", ".python-version"} {
				if a.inputProtected(root+"/"+file, cwd) {
					a.reason = roles.FileInput
					return true
				}
			}
		}
	}
	if len(args) == 0 {
		if !help {
			a.reason = roles.Indeterminate
		}
		return true
	}
	if tool {
		args = append([]string(nil), args...)
		args[0] = packageChildExecutable(args[0])
	}
	if module {
		args = append([]string{"python3", "-m"}, args...)
	}
	a.command(args, depth+1, cwd, direct)
	return true
}
