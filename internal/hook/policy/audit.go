package policy

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

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
	return paths.ConfiguredProtected(name, cwd, "", a.home, a.credentialConfig()) || a.protected(name, cwd)
}

func (a *analyzer) treeProtected(root, cwd string) bool {
	if time.Now().After(a.deadline) || cwd == "" && !filepath.IsAbs(root) {
		return true
	}
	return paths.ConfiguredTreeProtected(root, cwd, a.home, a.credentialConfig()) || paths.TreeProtected(root, cwd, a.home)
}

// Append requires a known prior value for environment-sensitive names.
func (a *analyzer) hookAppend(key, value string, depth int, cwd string) {
	previous, known := a.env[key]
	if !known && (sensitiveIndirect(key) || gitShellEnv(key) || strings.HasPrefix(key, "LESS") || key == "POSIXLY_CORRECT") {
		a.reason = roles.Indeterminate
		return
	}
	a.hookAssignment(key, previous+value, depth, cwd)
}

// hookAssignment checks only variables interpreted by a shell, never ordinary
// assignment data. No assignment value is evaluated to determine its contents.
func (a *analyzer) hookAssignment(key, value string, depth int, cwd string) {
	// Branches and scoped assignments cannot erase a possible credential path.
	if key == "KUBECONFIG" || key == "AWS_CONFIG_FILE" || key == "AWS_SHARED_CREDENTIALS_FILE" {
		// The retained representation is a native path list. Singular AWS
		// names containing its separator cannot be represented exactly.
		if key != "KUBECONFIG" && strings.ContainsRune(value, os.PathListSeparator) {
			a.reason = roles.Indeterminate
			return
		}
		if value != "" && !slices.Contains(a.credentialConfigs, value) {
			a.credentialConfigs = append(a.credentialConfigs, value)
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

// GNU env split-string has escapes which are not shell quoting. Decode these
// separators before parsing its child, rather than losing the backslash.
func splitEnv(s string) string {
	return strings.NewReplacer(`\_`, " ", `\t`, "\t", `\n`, "\n", `\r`, "\r").Replace(s)
}

func interpreter(name string) bool {
	return strings.HasPrefix(name, "python") || strings.Contains(" perl ruby node nodejs php awk gawk jq yq ", " "+name+" ")
}

// Interpreter literals share the shell/file credential classifier, including
// bare configured names and HOME/cwd-relative paths. Inspect names only; never
// evaluate source or open a credential to determine whether it is protected.
func (a *analyzer) interpreterProtected(code, cwd string) bool {
	for _, match := range inlinePath.FindAllStringSubmatch(code, -1) {
		if a.interpreterNameProtected(match[1], cwd) {
			return true
		}
	}
	for _, token := range strings.FieldsFunc(code, func(r rune) bool { return strings.ContainsRune(" \t\r\n\"'`(){}[];<>=,+", r) }) {
		if (strings.ContainsAny(token, "/\\") || paths.LexicalProtected(token, cwd, a.home) || paths.ConfiguredProtected(token, cwd, "", a.home, a.credentialConfig())) && a.interpreterNameProtected(token, cwd) {
			return true
		}
	}
	return false
}

// Long prose literals cannot be filesystem components. Keep lexical and
// configured witnesses even for impossible names, but do not turn ENAMETOOLONG
// from ordinary text into a credential read. Plausible paths still fail closed.
func (a *analyzer) interpreterNameProtected(name, cwd string) bool {
	if paths.LexicalProtected(name, cwd, a.home) || paths.ConfiguredProtected(name, cwd, "", a.home, a.credentialConfig()) {
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
func (a *analyzer) interpreterProducer(left *syntax.Stmt, producerCWD, cwd string) bool {
	var source strings.Builder
	syntax.NewPrinter().Print(&source, left)
	if a.interpreterProtected(source.String(), cwd) {
		return true
	}
	// Serialized shell source retains escapes around the interpreter's own
	// filename quotes. Inspect decoded producer words as positive witnesses,
	// not as certification of stdout or execution of printf/echo/cat. The
	// shared expander enforces word and deadline bounds without running code.
	protected := false
	inspect := func(word *syntax.Word) {
		values, known := a.expandWord(word, producerCWD)
		if known {
			for _, value := range values {
				protected = protected || a.interpreterProtected(value, cwd)
			}
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
				body, known := a.expandInterpreterStdin(node.Hdoc, true, producerCWD)
				if !known {
					a.reason = roles.Indeterminate
					protected = true
				} else {
					protected = protected || a.interpreterProtected(body, cwd)
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
	if strings.HasPrefix(name, "python") && len(args) >= 3 && args[0] == "-m" && args[1] == "dotenv" && optionIn("list get", args[2]) {
		a.reason = roles.Printer
		return true
	}
	if interpreter(name) || name == "sed" || name == "vim" || name == "vi" || name == "nvim" || name == "ex" {
		skip := 0
		for i, code := range args {
			if skip > 0 {
				skip--
				continue
			}
			if (name == "jq" || name == "yq") && (code == "--arg" || code == "--argjson" || code == "--rawfile" || code == "--slurpfile") {
				skip = 2
				continue
			}
			if (name == "node" || name == "nodejs") && (code == "--env-file" || strings.HasPrefix(code, "--env-file=") || i > 0 && args[i-1] == "--env-file") {
				continue
			}
			if interpreter(name) && name != "jq" && environmentCode(code) && !direct {
				a.reason = roles.Printer
				return true
			}
			if name != "jq" && name != "yq" && a.interpreterProtected(code, cwd) {
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
	return paths.ConfiguredTreeProtected(root, cwd, a.home, a.credentialConfig()) || paths.TreeProtectedScope(root, cwd, a.home, true)
}

func invalidControls(source string) bool {
	return strings.IndexFunc(source, func(r rune) bool { return r < 32 && r != '\n' && r != '\t' || r == 127 }) >= 0
}

// Keep every literal credential config path across shell branches.
func (a *analyzer) credentialConfig() string {
	config := strings.Join(a.credentialConfigs, string(os.PathListSeparator))
	if inherited := os.Getenv("KUBECONFIG"); inherited != "" {
		config = inherited + string(os.PathListSeparator) + config
	}
	return config
}
