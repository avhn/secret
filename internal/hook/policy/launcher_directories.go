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
	"--reinstall-package --no-binary-package --no-build-package --no-build-isolation-package --python-platform"

// uvRunChild consumes global and run options before selecting the executable.
// --directory changes the child cwd; --project selects metadata, not a cwd.
func (a *analyzer) uvRunChild(args []string, depth int, cwd string, direct bool) bool {
	if a.configArgument("uv", args, cwd) {
		return true
	}
	base, run, module := cwd, false, false
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
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
			if key == "--directory" {
				cwd = a.resolve(value, base)
			}
			if optionIn("--config-file --with-requirements", key) && a.inputProtected(value, base) {
				a.reason = roles.FileInput
				return true
			}
			continue
		}
		if !attached && optionIn("--module -m", key) && run {
			module = true
			continue
		}
		if !attached && optionIn("--no-project --no-sync --no-env-file --isolated --locked --frozen --active --all-extras --no-dev --only-dev --all-groups --no-default-groups --no-editable --no-sources --no-config --offline --no-cache -n --quiet -q --verbose -v --native-tls --managed-python --no-managed-python --no-python-downloads --no-progress --compile-bytecode --help -h --version -V --script", key) {
			continue
		}
		a.reason = roles.Indeterminate
		return true
	}
	if !run {
		return false
	}
	if len(args) == 0 {
		a.reason = roles.Indeterminate
		return true
	}
	if module {
		args = append([]string{"python3", "-m"}, args...)
	}
	a.command(args, depth+1, cwd, direct)
	return true
}
