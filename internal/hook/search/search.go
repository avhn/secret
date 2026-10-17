// Package search certifies search scope with metadata only.
package search

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
)

const ScopeReason = "search content/count scope contains protected names or is incomplete; narrow the path or use -l; install examples/ripgreprc for rg"
const UncertainReason = "search scope is uncertain; narrow the path or use -l; install examples/ripgreprc for rg"

var required = []string{".env", ".envrc", ".env.*", "*.env", "*.secret", ".secrets/", ".netrc", ".git-credentials", ".npmrc", ".pypirc", "**/.aws/credentials", "**/.aws/config", "**/.docker/config.json", "**/gh/hosts.yml", "**/.ssh/id_*", "**/.kube/config", "application_default_credentials.json", "**/gcloud/credentials.db", "**/gcloud/access_tokens.db", "**/gcloud/legacy_credentials/", ".vault-token", "**/.terraform.d/credentials.tfrc.json", "**/.cargo/credentials.toml", "**/.cargo/credentials", ".pgpass", ".yarnrc.yml"}

// Config returns 0 for certified, 1 for absent or partial, 2 for unsafe.
func Config(file, cwd, home string) (int, bool) {
	if file == "" {
		return 1, false
	}
	// RIPGREP_CONFIG_PATH is a native filesystem path, not shell text.
	if !filepath.IsAbs(file) {
		file = filepath.Join(cwd, file)
	}
	if paths.Protected(file, cwd, "", home) {
		return 2, false
	}
	info, err := os.Stat(file)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return 2, false
	}
	f, err := os.Open(file)
	if err != nil {
		return 2, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(data) > 8192 {
		return 2, false
	}
	seen := make(map[string]bool)
	hidden := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, b := range []byte(line) {
			if b < 32 && b != 9 || b == 127 {
				return 2, false
			}
		}
		switch {
		case line == "--hidden":
			hidden = true
		case strings.HasPrefix(line, "--iglob=!"):
			seen[strings.TrimPrefix(line, "--iglob=!")] = true
		case strings.HasPrefix(line, "--glob=!"):
		case neutral(line):
		default:
			return 2, false
		}
	}
	for _, v := range required {
		if !seen[v] {
			return 1, hidden
		}
	}
	if os.Getenv("KUBECONFIG") != "" || os.Getenv("AWS_CONFIG_FILE") != "" || os.Getenv("AWS_SHARED_CREDENTIALS_FILE") != "" {
		// Arbitrary configured names are not covered by the static exclusions.
		return 1, hidden
	}
	return 0, hidden
}
func neutral(s string) bool {
	for _, v := range []string{"--smart-case", "--ignore-case", "--case-sensitive", "--max-columns-preview", "--column", "--no-column", "--line-number", "--no-line-number", "--heading", "--no-heading", "--trim", "--no-messages"} {
		if s == v {
			return true
		}
	}
	for _, v := range []string{"--max-columns=", "--color=", "--colors=", "--sort=", "--sortr=", "--max-filesize=", "--threads="} {
		if strings.HasPrefix(s, v) {
			return true
		}
	}
	return false
}

// Selector tests synthetic candidate names, never contents.
func Selector(glob string) bool {
	if len(glob) > 4096 {
		return true
	}
	glob = strings.ReplaceAll(glob, "[!", "[^")
	if strings.Contains(glob, "{") {
		alternatives, ok := selectorBraces(glob, 64)
		if !ok {
			return true
		}
		for _, alternative := range alternatives {
			if Selector(alternative) {
				return true
			}
		}
		return false
	}
	if paths.LexicalProtected(glob, "/synthetic", "/synthetic") {
		return true
	}
	// Derive witnesses from the selector itself so arbitrary environment names
	// such as .en[v].staging* are not limited to a finite sample dictionary.
	for _, star := range []string{"", "x"} {
		candidate, valid := selectorWitness(glob, star)
		if !valid || paths.LexicalProtected(candidate, "/synthetic", "/synthetic") {
			return true
		}
	}
	// Complete a wildcarded .env prefix with its literal suffix. This also
	// covers .en?.staging* and .???.production*, which no finite sample list
	// can enumerate. Bound the prefix work independently of directory depth.
	base := path.Base(glob)
	limit := min(len(base), 256)
	for i := 1; i <= limit && (strings.HasPrefix(base, ".") || strings.HasPrefix(base, "[.]")); i++ {
		if match, err := path.Match(base[:i], ".env"); err == nil && match {
			if suffix, valid := selectorWitness(base[i:], "x"); !valid || paths.LexicalProtected(".env"+suffix, "/synthetic", "/synthetic") {
				return true
			}
		}
	}
	if len(base) > 256 && strings.ContainsAny(base, "*?[") {
		return true
	}
	if strings.Contains(glob, "/") && Selector(path.Base(glob)) {
		return true
	}
	g := strings.ToLower(strings.TrimPrefix(glob, "!"))
	for _, name := range []string{".env", ".envrc", ".env.production", "service.env", "service.secret", ".secrets.env", ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".vault-token", ".pgpass", ".yarnrc.yml", ".kube/config", "application_default_credentials.json", ".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db", ".config/gcloud/legacy_credentials/token", ".terraform.d/credentials.tfrc.json", ".cargo/credentials.toml", ".cargo/credentials", ".secrets/store", ".aws/credentials", ".aws/config", ".docker/config.json", ".config/gh/hosts.yml", ".ssh/id_rsa", ".ssh/id_ed25519", "proc/self/environ", "proc/thread-self/environ", "proc/123/environ", "proc/123/task/456/environ", "proc/$$/environ", "proc/$ppid/environ"} {
		if strings.Contains(name, "/") && !strings.Contains(g, "/") {
			continue
		}
		for _, v := range []string{g, strings.TrimPrefix(g, "**/")} {
			// A selector with a directory component can also match protected
			// basenames below an ordinary search root.
			for _, candidate := range []string{name, "src/" + name} {
				if ok, _ := path.Match(v, candidate); ok {
					return true
				}
			}
		}
	}
	return false
}

// ToolGlob protects only explicit roots; Glob returns names, not file bytes.
func ToolGlob(root, cwd, home string) string {
	if root != "" && paths.Protected(root, cwd, "", home) {
		return "file access targets a protected store"
	}
	return ""
}

// ToolGrep checks Claude Grep names and content modes.
func ToolGrep(root, glob, typ, mode, cwd, home string) string {
	if root == "" {
		root = cwd
	}
	if mode == "" {
		mode = "files_with_matches"
	}
	names := mode == "files_with_matches"
	switch strings.ToLower(typ) {
	case "env", "dotenv", "secret", "secrets", "netrc", "git-credentials":
		if !names {
			return "Grep type targets protected names"
		}
	}
	if positiveGlob(glob) && !CanNarrow(glob) && Selector(glob) && (!names || !strings.ContainsAny(glob, "*?[")) {
		return "Grep selector targets protected names"
	}
	if paths.Protected(root, cwd, "", home) {
		p := paths.Resolve(root, cwd, "", home)
		info, err := os.Lstat(p)
		if !names || paths.LexicalProtected(root, cwd, home) || err != nil || info.Mode()&os.ModeSymlink == 0 {
			return "Grep targets a protected store"
		}
	}
	if !names && (CanNarrow(glob) || glob == "" && typeGlob(typ) != "") {
		return FilteredScope(root, glob, typ, cwd, home)
	}
	if !names && paths.TreeProtectedScope(root, cwd, home, glob != "") {
		return "Grep content/count tree contains protected names or its scan is incomplete (depth, error, deadline); use files_with_matches or narrow the path"
	}
	return ""
}

// Scope checks already expanded shell words. Config is trusted only when the
// caller proves no wrapper or inline assignment changed its environment.
func Scope(words []string, cwd, home, config string, inlineConfig bool) string {
	if len(words) == 0 {
		return ""
	}
	kind := path.Base(words[0])
	start := 1
	uncertain := false
	if kind == "git" {
		for start < len(words) && words[start] != "grep" {
			switch words[start] {
			case "-C":
				start++
				if start >= len(words) {
					return UncertainReason
				}
				cwd = paths.Resolve(words[start], cwd, "", home)
			case "-c", "--git-dir", "--work-tree", "--config-env":
				uncertain = true
				start++
			case "--no-pager", "--paginate", "--no-optional-locks":
			default:
				uncertain = true
			}
			start++
		}
		if start == len(words) {
			return ""
		}
		start++
	} else if kind != "rg" {
		return ""
	}
	names, count, pattern, options, positive, includeIgnored := false, false, true, true, false, false
	unsafeScope := false
	unsafeNames := false
	gitWorkTree := false
	outputOnly, jsonOutput, negativeSelector := false, false, false
	var selectors []string
	roots := []string{}
	args := words[start:]
	for i := 0; i < len(args); i++ {
		v := args[i]
		if options {
			v = searchLongOption(v, kind)
			if v == "--pre" || strings.HasPrefix(v, "--pre=") {
				return UncertainReason
			}
			if v == "--" {
				options = false
				continue
			}
			switch v {
			case "-l", "--files-with-matches", "--files-without-match":
				names = true
				continue
			case "--files":
				if kind == "rg" {
					names = true
				}
				continue
			case "-q", "--quiet":
				outputOnly = true
				continue
			case "-c", "--count", "--count-matches":
				count, outputOnly = true, true
				continue
			case "--json":
				count, outputOnly, jsonOutput = true, false, true
				continue
			case "--no-index", "--no-exclude-standard":
				if kind == "git" {
					includeIgnored, gitWorkTree = true, true
					continue
				}
			case "--untracked":
				if kind == "git" {
					gitWorkTree = true
					continue
				}
			case "--hidden":
				includeIgnored = true
				continue
			case "--follow", "--search-zip", "--no-ignore", "--no-ignore-vcs", "--no-ignore-parent", "--no-ignore-dot", "--no-config", "--ignore-file-case-insensitive":
				unsafeScope, includeIgnored = true, true
				continue
			case "-g", "--glob", "--iglob":
				i++
				if i >= len(args) {
					return UncertainReason
				}
				if positiveGlob(args[i]) {
					selectors = append(selectors, args[i])
				} else {
					negativeSelector = true
				}
				positive = positive || !NegativeGlob(args[i])
				includeIgnored = true
				continue
			case "-e", "--regexp", "-f", "--file":
				i++
				if i >= len(args) {
					return UncertainReason
				}
				pattern = false
				if (v == "-f" || v == "--file") && args[i] != "-" && paths.RootProtected(args[i], cwd, home) {
					return "pattern file targets a protected store"
				}
				continue
			case "-t", "--type", "-T", "--type-not", "--type-add", "-A", "-B", "-C", "-m", "--max-count", "--context", "--after-context", "--before-context", "--encoding", "--color", "--colors", "--max-depth", "--threads", "-j", "--pre-glob", "--ignore-file", "--pre":
				if v == "--pre" || v == "--ignore-file" || v == "--pre-glob" {
					unsafeScope = true
				}
				i++
				if i >= len(args) {
					return UncertainReason
				}
				includeIgnored = true
				continue
			}
			if strings.HasPrefix(v, "--glob=") || strings.HasPrefix(v, "--iglob=") || strings.HasPrefix(v, "-g") && len(v) > 2 {
				g := strings.TrimPrefix(strings.TrimPrefix(v, "--glob="), "--iglob=")
				g = strings.TrimPrefix(g, "-g")
				if positiveGlob(g) {
					selectors = append(selectors, g)
				} else {
					negativeSelector = true
				}
				positive = positive || !NegativeGlob(g)
				includeIgnored = true
				continue
			}
			if strings.HasPrefix(v, "--file=") || strings.HasPrefix(v, "-f") && len(v) > 2 {
				f := strings.TrimPrefix(strings.TrimPrefix(v, "--file="), "-f")
				if f != "-" && paths.RootProtected(f, cwd, home) {
					return "pattern file targets a protected store"
				}
				pattern = false
				continue
			}
			if strings.HasPrefix(v, "--regexp=") || strings.HasPrefix(v, "-e") && len(v) > 2 {
				pattern = false
				continue
			}
			if kind == "rg" && (strings.HasPrefix(v, "-t") && len(v) > 2 || strings.HasPrefix(v, "--type=")) {
				includeIgnored = true
				continue
			}
			if kind == "rg" && strings.HasPrefix(v, "-T") && len(v) > 2 {
				includeIgnored = true
				continue
			}
			if strings.HasPrefix(v, "--type-not=") || strings.HasPrefix(v, "--type-add=") || strings.HasPrefix(v, "--max-depth=") || strings.HasPrefix(v, "--color=") || strings.HasPrefix(v, "--colors=") || strings.HasPrefix(v, "--encoding=") || strings.HasPrefix(v, "--max-count=") || strings.HasPrefix(v, "--threads=") || strings.HasPrefix(v, "--context=") {
				continue
			}
			if kind == "git" && (v == "-O" || strings.HasPrefix(v, "-O") || strings.HasPrefix(v, "--open-files-in-pager")) {
				return UncertainReason
			}
			if strings.HasPrefix(v, "-") {
				if strings.HasPrefix(v, "--") {
					if !neutral(v) && !simple(v) {
						if v != "--cached" && v != "--no-index" && v != "--untracked" {
							unsafeNames = true
						}
						uncertain = true
					}
					continue
				}
				valid := true
				for _, c := range v[1:] {
					if !strings.ContainsRune("niIsSFwxoHvqahNUPlc0u", c) {
						valid = false
					}
					if c == 'l' {
						names = true
					}
					if c == 'c' {
						count, outputOnly = true, true
					}
					if c == 'q' {
						outputOnly = true
					}
					if c == 'u' {
						unsafeScope, includeIgnored = true, true
					}
				}
				if !valid {
					unsafeNames = true
					uncertain = true
				}
				continue
			}
		}
		if pattern {
			pattern = false
			continue
		}
		if kind == "git" && options && !gitWorkTree {
			uncertain = true
		}
		if strings.ContainsAny(v, "*?[`$") {
			uncertain = true
		}
		roots = append(roots, v)
	}
	if kind == "rg" && outputOnly && !jsonOutput && len(roots) > 0 && !unsafeNames {
		filesOnly := true
		for _, root := range roots {
			if info, err := os.Stat(paths.Resolve(root, cwd, "", home)); err == nil && info.IsDir() {
				filesOnly = false
			}
		}
		if filesOnly {
			return ""
		}
	}
	if names && !count && !unsafeNames {
		return ""
	}
	if uncertain || unsafeScope {
		return UncertainReason
	}
	if len(roots) == 0 {
		roots = []string{cwd}
	}
	// Explicit HOME/.aws content roots retain the Bash guard's lexical
	// protection even under a certified exclusion config. Names-only modes
	// have already returned; config certification cannot widen this input.
	for _, root := range roots {
		if paths.Protected(root, cwd, "", home) || paths.Resolve(root, cwd, "", home) == filepath.Join(home, ".aws") {
			return "explicit search input is protected"
		}
		if _, err := os.Lstat(paths.Resolve(root, cwd, "", home)); err == nil && paths.RootProtected(root, cwd, home) {
			return "explicit search input is protected or cannot be resolved safely"
		}
	}
	certified := false
	if kind == "rg" {
		if inlineConfig {
			return "rg config cannot establish safe search inputs"
		}
		status, hidden := Config(config, cwd, home)
		if status == 2 {
			return "rg config cannot establish safe search inputs"
		}
		certified = status == 0 && !positive && !unsafeScope
		if len(selectors) > 0 && !negativeSelector {
			safe := true
			for _, selector := range selectors {
				if !CanNarrow(selector) {
					safe = false
				}
			}
			if safe {
				for _, root := range roots {
					for _, selector := range selectors {
						if FilteredScope(root, strings.ToLower(selector), "", cwd, home) != "" {
							return ScopeReason
						}
					}
				}
				return ""
			}
		}
		if hidden {
			includeIgnored = true
		}
	}
	if certified {
		for _, root := range roots {
			for _, component := range strings.Split(filepath.ToSlash(paths.Resolve(root, cwd, "", home)), "/") {
				if component == ".git" || component == "node_modules" {
					certified = false
					break
				}
			}
		}
	}
	if certified {
		return ""
	}
	for _, root := range roots {
		if paths.TreeProtectedScope(root, cwd, home, includeIgnored) {
			return ScopeReason
		}
	}
	return ""
}
func simple(v string) bool {
	for _, f := range []string{"--line-number", "--no-line-number", "--ignore-case", "--case-sensitive", "--smart-case", "--fixed-strings", "--word-regexp", "--line-regexp", "--heading", "--no-heading", "--with-filename", "--no-filename", "--text", "--null", "--null-data", "--only-matching", "--invert-match", "--quiet", "--pcre2", "--multiline", "--multiline-dotall", "--stats"} {
		if v == f {
			return true
		}
	}
	return false
}

// selectorBraces enumerates bounded selector lists without shell expansion.
// Unknown or malformed brace forms cannot certify a content selector as safe.
func selectorBraces(pattern string, budget int) ([]string, bool) {
	return selectorBracesAt(pattern, budget, 0)
}

func selectorBracesAt(pattern string, budget, nesting int) ([]string, bool) {
	if nesting > 16 || budget < 1 {
		return nil, false
	}
	start := strings.IndexByte(pattern, '{')
	if start < 0 {
		return []string{pattern}, true
	}
	depth, end := 0, -1
	for i := start; i < len(pattern); i++ {
		if pattern[i] == '{' {
			depth++
		}
		if pattern[i] == '}' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return nil, false
	}
	var out []string
	body := pattern[start+1 : end]
	parts, last, depth := []string{}, 0, 0
	for i, c := range body {
		if c == '{' {
			depth++
		}
		if c == '}' {
			depth--
		}
		if c == ',' && depth == 0 {
			parts = append(parts, body[last:i])
			last = i + 1
		}
	}
	parts = append(parts, body[last:])
	if len(parts) > budget {
		return nil, false
	}
	for _, part := range parts {
		values, ok := selectorBracesAt(pattern[:start]+part+pattern[end+1:], budget-len(out), nesting+1)
		if !ok || len(out)+len(values) > budget {
			return nil, false
		}
		out = append(out, values...)
	}
	return out, true
}

// searchLongOption resolves unique prefixes within the supported role table.
// Unknown or ambiguous spellings remain unknown and cannot unlock names mode.
func searchLongOption(arg, kind string) string {
	if !strings.HasPrefix(arg, "--") || arg == "--" {
		return arg
	}
	key, value, attached := strings.Cut(arg[2:], "=")
	names := "regexp file files-with-matches files-without-match count ignore-case fixed-strings word-regexp line-regexp line-number no-line-number with-filename no-filename text null null-data only-matching invert-match quiet color after-context before-context context max-count"
	if kind == "git" {
		names += " open-files-in-pager cached no-index untracked exclude-standard no-exclude-standard basic-regexp extended-regexp perl-regexp full-name all-match break heading show-function function-context"
	} else {
		names += " files count-matches json hidden follow search-zip no-ignore no-ignore-vcs no-ignore-parent no-ignore-dot no-config ignore-file-case-insensitive glob iglob type type-not type-add encoding colors max-depth threads pre pre-glob ignore-file smart-case case-sensitive max-columns-preview column no-column heading no-heading trim no-messages max-columns sort sortr max-filesize pcre2 multiline multiline-dotall stats"
	}
	match := ""
	for _, name := range strings.Fields(names) {
		if key == name {
			return arg
		}
		if key != "" && strings.HasPrefix(name, key) {
			if match != "" {
				return arg
			}
			match = name
		}
	}
	if match == "" {
		return arg
	}
	if attached {
		return "--" + match + "=" + value
	}
	return "--" + match
}
