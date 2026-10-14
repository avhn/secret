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

var required = []string{".env", ".env.*", "*.env", "*.secret", ".secrets/", ".netrc", ".git-credentials", ".npmrc", ".pypirc", "**/.aws/credentials", "**/.docker/config.json", "**/gh/hosts.yml", "**/.ssh/id_*"}

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
	if strings.Contains(glob, "/") && Selector(path.Base(glob)) {
		return true
	}
	g := strings.ToLower(strings.TrimPrefix(glob, "!"))
	for _, name := range []string{".env", ".env.production", "service.env", "service.secret", ".secrets.env", ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".secrets/store", ".aws/credentials", ".docker/config.json", ".config/gh/hosts.yml", ".ssh/id_rsa", ".ssh/id_ed25519", "proc/self/environ", "proc/thread-self/environ", "proc/123/environ", "proc/123/task/456/environ", "proc/$$/environ", "proc/$ppid/environ"} {
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
	if glob != "" && Selector(glob) && (!names || !strings.ContainsAny(glob, "*?[")) {
		return "Grep selector targets protected names"
	}
	if paths.Protected(root, cwd, "", home) {
		p := paths.Resolve(root, cwd, "", home)
		info, err := os.Lstat(p)
		if !names || paths.LexicalProtected(root, cwd, home) || err != nil || info.Mode()&os.ModeSymlink == 0 {
			return "Grep targets a protected store"
		}
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
	roots := []string{}
	args := words[start:]
	for i := 0; i < len(args); i++ {
		v := args[i]
		if options {
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
			case "-c", "--count", "--count-matches", "--json":
				count = true
				continue
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
				positive = positive || !strings.HasPrefix(args[i], "!")
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
				positive = positive || !strings.HasPrefix(g, "!")
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
			if strings.HasPrefix(v, "--type=") || strings.HasPrefix(v, "--type-not=") || strings.HasPrefix(v, "--type-add=") || strings.HasPrefix(v, "--max-depth=") || strings.HasPrefix(v, "--color=") || strings.HasPrefix(v, "--colors=") || strings.HasPrefix(v, "--encoding=") || strings.HasPrefix(v, "--max-count=") || strings.HasPrefix(v, "--threads=") || strings.HasPrefix(v, "--context=") {
				continue
			}
			if kind == "git" && (v == "-O" || strings.HasPrefix(v, "-O") || strings.HasPrefix(v, "--open-files-in-pager")) {
				return UncertainReason
			}
			if strings.HasPrefix(v, "-") {
				if strings.HasPrefix(v, "--") {
					if !neutral(v) && !simple(v) {
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
						count = true
					}
					if c == 'u' {
						unsafeScope, includeIgnored = true, true
					}
				}
				if !valid {
					uncertain = true
				}
				continue
			}
		}
		if pattern {
			pattern = false
			continue
		}
		if kind == "git" && options {
			uncertain = true
		}
		if strings.ContainsAny(v, "*?[`$") {
			uncertain = true
		}
		roots = append(roots, v)
	}
	if names && !count {
		return ""
	}
	if uncertain || unsafeScope {
		return UncertainReason
	}
	if len(roots) == 0 {
		roots = []string{cwd}
	}
	for _, root := range roots {
		if paths.Protected(root, cwd, "", home) {
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
	if len(parts) < 2 || len(parts) > budget {
		return nil, false
	}
	for _, part := range parts {
		values, ok := selectorBraces(pattern[:start]+part+pattern[end+1:], budget-len(out))
		if !ok || len(out)+len(values) > budget {
			return nil, false
		}
		out = append(out, values...)
	}
	return out, true
}
