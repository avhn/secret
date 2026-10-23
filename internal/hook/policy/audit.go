package policy

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

func (a *analyzer) pathMetadata() *paths.Metadata {
	if a.metadata == nil {
		a.metadata = new(paths.Metadata)
	}
	return a.metadata
}

// inputProtected keeps unknown shell directories and process-relative aliases
// out of the filesystem existence exception for bare operands.
func (a *analyzer) inputProtected(name, cwd string) bool {
	// Web addresses are values, not local file inputs. file:// remains a
	// filesystem access and is handled by the normal protected-name checks.
	if strings.HasPrefix(name, "https://") || strings.HasPrefix(name, "http://") {
		return false
	}
	if base := paths.StreamBase(name); base != name {
		// An absent stream must not bypass protection of its base file through
		// the shell callback's bare-operand existence exception.
		return paths.Protected(base, cwd, "", a.home)
	}
	p := path.Clean(name)
	if paths.ProcessAlias(p) {
		return true
	}
	if cwd == "" && !filepath.IsAbs(name) {
		return true
	}
	return a.pathMetadata().ConfiguredProtected(name, cwd, "", a.home, a.credentialConfig(), a.credentialPaths()...) || a.protected(name, cwd)
}

func (a *analyzer) treeProtected(root, cwd string) bool {
	if time.Now().After(a.deadline) || cwd == "" && !filepath.IsAbs(root) {
		return true
	}
	return paths.ConfiguredTreeProtected(root, cwd, a.home, a.credentialConfig(), a.credentialPaths()...) || paths.TreeProtected(root, cwd, a.home)
}

// Append requires a known prior value for environment-sensitive names.
func (a *analyzer) hookAppend(key, value string, depth int, cwd string) {
	previous, known := a.env[key]
	if !known && (sensitiveIndirect(key) || gitShellEnv(key) || strings.HasPrefix(key, "LESS") || key == "POSIXLY_CORRECT") {
		a.reason = roles.Indeterminate
		return
	}
	a.noteArithmeticAppend(key, value)
	a.hookAssignment(key, previous+value, depth, cwd)
}

type credentialConfig struct {
	key, value string
}

// hookAssignment checks only variables interpreted by a shell, never ordinary
// assignment data. No assignment value is evaluated to determine its contents.
func (a *analyzer) hookAssignment(key, value string, depth int, cwd string) {
	a.noteArithmeticValue(key, value)
	// Branches and scoped assignments cannot erase a possible credential path.
	if optionIn("KUBECONFIG AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE XDG_CONFIG_HOME GH_CONFIG_DIR", key) {
		if !a.credentialBranch {
			a.credentialConfigs = slices.DeleteFunc(a.credentialConfigs, func(config credentialConfig) bool { return config.key == key })
		}
		target := value
		if key == "XDG_CONFIG_HOME" || key == "GH_CONFIG_DIR" {
			target = paths.GHHostsPath(key, value)
		}
		config := credentialConfig{key, target}
		if target != "" && !slices.Contains(a.credentialConfigs, config) {
			a.credentialConfigs = append(a.credentialConfigs, config)
		}
	}
	if a.env == nil {
		a.env = make(map[string]string)
	}
	if previous, ok := a.env[key]; ok && previous != value {
		a.env[key] = "" // Branches and scoped assignments cannot certify a replacement.
	} else {
		a.env[key] = value
	}
	if key == "POSIXLY_CORRECT" {
		a.env[key] = value
	}
	if key == "GIT_EXEC_PATH" {
		a.reason = roles.Indeterminate
		return
	}
	if gitShellEnv(key) {
		a.editorPagerValue(key, value, cwd)
	}
	if strings.HasPrefix(key, "LESS") && key != "LESS" || key == "LESS" && !inertLessOption("-"+value) {
		a.reason = roles.Indeterminate
		return
	}
	switch key {
	case "BASH_ENV", "ENV":
		if value == "" || a.inputProtected(value, cwd) {
			a.reason = roles.FileInput
		} else if key == "BASH_ENV" {
			// A child shell sources this file; its code and path options are unknown.
			a.reason = roles.Indeterminate
		}
	case "SHELLOPTS", "BASHOPTS":
		if value == "" {
			a.reason = roles.Indeterminate
			return
		}
		for _, option := range strings.Split(value, ":") {
			if shellPathOption(option) {
				a.cdpath = true
			}
		}
	case "PS4", "PROMPT_COMMAND":
		if value == "" {
			a.reason = roles.Indeterminate
			return
		}
		a.fragmentAt(value, depth+1, cwd)
	}
}

// scopedGHConfig keeps new gh directory witnesses local to child environments.
// Retain the older conservative scope rules for other credential providers.
func (a *analyzer) scopedGHConfig() func() {
	isGH := func(config credentialConfig) bool {
		return config.key == "XDG_CONFIG_HOME" || config.key == "GH_CONFIG_DIR"
	}
	var parent []credentialConfig
	for _, config := range a.credentialConfigs {
		if isGH(config) {
			parent = append(parent, config)
		}
	}
	xdg, xdgKnown := a.env["XDG_CONFIG_HOME"]
	gh, ghKnown := a.env["GH_CONFIG_DIR"]
	return func() {
		a.credentialConfigs = append(slices.DeleteFunc(a.credentialConfigs, isGH), parent...)
		for key, value := range map[string]string{"XDG_CONFIG_HOME": xdg, "GH_CONFIG_DIR": gh} {
			known := xdgKnown
			if key == "GH_CONFIG_DIR" {
				known = ghKnown
			}
			if !known {
				delete(a.env, key)
			} else {
				if a.env == nil {
					a.env = make(map[string]string)
				}
				a.env[key] = value
			}
		}
	}
}

// GNU env split-string has escapes which are not shell quoting. Decode these
// separators before parsing its child, rather than losing the backslash.
func splitEnv(s string) string {
	return strings.NewReplacer(`\_`, " ", `\t`, "\t", `\n`, "\n", `\r`, "\r").Replace(s)
}

var pypyVersion = regexp.MustCompile(`^pypy(?:[0-9][a-z0-9._-]*)?$`)

// Python-compatible executable names share every interpreter and module role.
func pythonInterpreter(name string) bool {
	return strings.HasPrefix(name, "python") || pypyVersion.MatchString(name)
}

var luaVersion = regexp.MustCompile(`^lua(?:jit)?(?:[0-9._-][a-z0-9._-]*)?$`)

func javascriptInterpreter(name string) bool {
	return optionIn("node nodejs bun deno", name)
}

func interpreter(name string) bool {
	return pythonInterpreter(name) || luaVersion.MatchString(name) || strings.Contains(" perl ruby node nodejs bun deno php rscript awk gawk jq yq ", " "+name+" ")
}

// Interpreter literals share the shell/file credential classifier, including
// bare configured names and HOME/cwd-relative paths. Inspect names only; never
// evaluate source or open a credential to determine whether it is protected.
func (a *analyzer) interpreterProtected(code, cwd string) bool {
	values, known := a.sourceLiterals(code)
	if !known {
		return true
	}
	for _, value := range values {
		if a.interpreterBudget(false) || a.interpreterNameProtected(value, cwd) {
			return true
		}
	}
	for _, token := range strings.FieldsFunc(code, func(r rune) bool { return strings.ContainsRune(" \t\r\n\"'`(){}[];<>=,+", r) }) {
		if a.interpreterBudget(false) {
			return true
		}
		if (strings.ContainsAny(token, "/\\") || a.pathMetadata().LexicalProtected(token, cwd, a.home) || a.pathMetadata().ConfiguredProtected(token, cwd, "", a.home, a.credentialConfig(), a.credentialPaths()...)) && a.interpreterNameProtected(token, cwd) {
			return true
		}
	}
	return false
}

// Long prose literals cannot be filesystem components. Keep lexical and
// configured witnesses even for impossible names, but do not turn ENAMETOOLONG
// from ordinary text into a credential read. Plausible paths still fail closed.
func (a *analyzer) interpreterNameProtected(name, cwd string) bool {
	key := interpreterName{name, cwd, a.credentialConfig() + "\x00" + strings.Join(a.credentialPaths(), "\x00")}
	if protected, ok := a.interpreterNames[key]; ok {
		return protected
	}
	protected := a.checkInterpreterName(name, cwd)
	if a.interpreterNames == nil {
		a.interpreterNames = make(map[interpreterName]bool)
	}
	if len(a.interpreterNames) < 4096 {
		a.interpreterNames[key] = protected
	}
	return protected
}

func (a *analyzer) checkInterpreterName(name, cwd string) bool {
	if a.pathMetadata().LexicalProtected(name, cwd, a.home) || a.pathMetadata().ConfiguredProtected(name, cwd, "", a.home, a.credentialConfig(), a.credentialPaths()...) {
		return true
	}
	for _, component := range strings.FieldsFunc(name, func(r rune) bool { return r == '/' || r == '\\' }) {
		if utf8.RuneCountInString(component) > 255 {
			return false
		}
	}
	return a.inputProtected(name, cwd)
}

// Literal producers may supply interpreter source through stdin instead of an
// attached heredoc. Inspect names only, never execute or certify producer output.
func (a *analyzer) interpreterProducer(left *syntax.Stmt, producerCWD, cwd, name string) bool {
	var source strings.Builder
	syntax.NewPrinter().Print(&source, left)
	// Serialized shell quoting is not an interpreter literal boundary. Retain
	// the environment witness here; path and literal ceilings are checked on
	// every decoded producer word below, not on shell quote-escape fragments.
	if environmentCode(source.String()) {
		return true
	}
	// Serialized shell source retains escapes around the interpreter's own
	// filename quotes. Inspect decoded producer words as positive witnesses,
	// not as certification of stdout or execution of printf/echo/cat. The
	// shared expander enforces word and deadline bounds without running code.
	protected := false
	inspect := func(word *syntax.Word) {
		values, known := a.expandWord(word, producerCWD)
		if !known {
			// Producer uncertainty is executable-input uncertainty, just like
			// a here-string. Retain it here, not only in the final shell check.
			a.reason = roles.Indeterminate
			protected = true
			return
		}
		for _, value := range values {
			protected = protected || a.executableInterpreterProtected(value, cwd, name)
		}
	}
	syntax.Walk(left, func(node syntax.Node) bool {
		if protected {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			for _, word := range node.Args {
				inspect(word)
			}
		case *syntax.Redirect:
			if node.Op == syntax.WordHdoc {
				inspect(node.Word)
			}
			if node.Hdoc != nil {
				body, known := a.interpreterRedirectBody(node, producerCWD)
				if !known {
					a.reason = roles.Indeterminate
					protected = true
				} else {
					protected = protected || a.executableInterpreterProtected(body, cwd, name)
				}
			}
		}
		return true
	})
	return protected
}

func environmentCode(code string) bool {
	lower := strings.ToLower(code)
	return strings.Contains(lower, "environ") || strings.Contains(code, "ENV") || strings.Contains(lower, "getenv") || strings.Contains(lower, "strenv") || strings.Contains(lower, "process") && strings.Contains(lower, "env") || strings.Contains(code, "-MEnv")
}

// auditCommand checks roles whose inputs are not ordinary positional files.
// It returns true only when it supplied a denial; normal dispatch still runs.
func (a *analyzer) auditCommand(name string, args []string, depth int, cwd string, direct bool) bool {
	if name == "sed" || name == "awk" || name == "gawk" {
		a.scriptInputs(name, args, depth, cwd)
	}
	if a.reason != "" {
		return true
	}
	if pythonInterpreter(name) && len(args) >= 3 && args[0] == "-m" && args[1] == "dotenv" && optionIn("list get", args[2]) {
		a.reason = roles.Printer
		return true
	}
	if interpreter(name) || name == "sed" || name == "vim" || name == "vi" || name == "nvim" || name == "ex" {
		codeArgs := args
		if interpreter(name) {
			var complete bool
			codeArgs, complete = interpreterCodeArgsComplete(name, args)
			if !complete {
				a.reason = roles.Indeterminate
				return true
			}
		}
		sourceArgs := interpreterSourceArgs(name, codeArgs)
		skip := 0
		for i, code := range codeArgs {
			if skip > 0 {
				skip--
				continue
			}
			if (name == "jq" || name == "yq") && (code == "--arg" || code == "--argjson" || code == "--rawfile" || code == "--slurpfile") {
				skip = 2
				continue
			}
			if (name == "node" || name == "nodejs") && (code == "--env-file" || strings.HasPrefix(code, "--env-file=") || i > 0 && codeArgs[i-1] == "--env-file") {
				continue
			}
			if interpreter(name) && name != "jq" && environmentCode(code) && !direct {
				a.reason = roles.Printer
				return true
			}
			if name != "jq" && name != "yq" && (a.interpreterProtected(code, cwd) || interpreter(name) && a.interpreterArgumentProtected(code, cwd, name, sourceArgs[i])) {
				a.reason = roles.FileInput
				return true
			}
			if name == "sed" {
				for j, r := range code {
					if r == 'e' && (j == 0 || code[j-1] >= '0' && code[j-1] <= '9') && j+1 < len(code) && code[j+1] == ' ' {
						a.fragmentAt(code[j+1:], depth+1, cwd)
					}
				}
			}
		}
	}
	if name == "jq" {
		a.jqInputs(args, cwd)
	}
	if name == "diff" {
		for _, arg := range args {
			if strings.HasPrefix(arg, "--from-file=") || strings.HasPrefix(arg, "--to-file=") {
				_, value, _ := strings.Cut(arg, "=")
				if a.inputProtected(value, cwd) {
					a.reason = roles.FileInput
				}
			}
		}
	}
	return a.reason != ""
}

func (a *analyzer) dotenvChild(args []string, depth int, cwd string) {
	for i := 0; i < len(args); i++ {
		v := args[i]
		switch v {
		case "--":
			a.command(args[i+1:], depth+1, cwd, false)
			return
		case "-p", "--print", "list", "get":
			a.reason = roles.Printer
			return
		case "run":
			continue
		case "-f", "--env-file", "-e", "--env", "-v", "--variable":
			i++
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return
			}
		case "-c", "--cascade":
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				if args[i] == "env" || args[i] == "printenv" {
					a.reason = roles.Printer
					return
				}
			}
		case "decrypt":
			if strings.Contains(strings.Join(args[i+1:], " "), "--stdout") {
				a.reason = roles.Printer
				return
			}
		case "--debug", "-o", "--override", "--no-expand":
		default:
			if strings.HasPrefix(v, "--print=") {
				a.reason = roles.Printer
				return
			}
			if strings.HasPrefix(v, "--env=") || strings.HasPrefix(v, "--variable=") || strings.HasPrefix(v, "--cascade=") {
				continue
			}
			if strings.HasPrefix(v, "-") {
				a.reason = roles.Indeterminate
				return
			}
			a.command(args[i:], depth+1, cwd, false)
			return
		}
	}
}

// A branch, zero-iteration loop or uncalled function can leave either cwd.
// Retain uncertainty rather than selecting the last syntactic directory.
func joinedCWD(before, after string) string {
	if before != after {
		return ""
	}
	return before
}

func (a *analyzer) treeProtectedAll(root, cwd string) bool {
	if time.Now().After(a.deadline) || cwd == "" && !filepath.IsAbs(root) {
		return true
	}
	return paths.ConfiguredTreeProtected(root, cwd, a.home, a.credentialConfig(), a.credentialPaths()...) || paths.TreeProtectedScope(root, cwd, a.home, true)
}

func invalidControls(source string) bool {
	return strings.IndexFunc(source, func(r rune) bool { return r < 32 && r != '\n' && r != '\t' || r == 127 }) >= 0
}

// Keep Kubernetes path lists separate from singular AWS and gh names.
func (a *analyzer) credentialConfig() string {
	var values []string
	for _, config := range a.credentialConfigs {
		if config.key == "KUBECONFIG" {
			values = append(values, config.value)
		}
	}
	config := strings.Join(values, string(os.PathListSeparator))
	if inherited := os.Getenv("KUBECONFIG"); inherited != "" {
		config = inherited + string(os.PathListSeparator) + config
	}
	return config
}

// Singular credential filenames may contain the native list separator.
func (a *analyzer) credentialPaths() []string {
	var values []string
	for _, config := range a.credentialConfigs {
		if config.key != "KUBECONFIG" {
			values = append(values, config.value)
		}
	}
	return values
}
