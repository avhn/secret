package policy

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"mvdan.cc/sh/v3/syntax"
)

// staticWriteTarget rejects patterns and computed names before path resolution.
func (a *analyzer) staticWriteTarget(value, cwd string) bool {
	if cwd == "" && !filepath.IsAbs(value) && !strings.HasPrefix(value, "~/") {
		return false
	}
	if strings.ContainsAny(value, "*?[]$`") {
		return false
	}
	return value != ""
}

func (a *analyzer) uncertainWriteWord(word *syntax.Word, cwd string) bool {
	if word == nil {
		return true
	}
	raw := a.raw(word)
	if strings.ContainsAny(raw, "*?[]`") {
		return true
	}
	if strings.Contains(raw, "$(") {
		return true
	}
	if strings.Contains(raw, "$") {
		for _, part := range word.Parts {
			switch n := part.(type) {
			case *syntax.ParamExp:
				if n.Param == nil || n.Exp != nil || n.Repl != nil || n.Slice != nil || n.Index != nil || n.Length || n.Excl {
					return true
				}
				if n.Param.Value != "HOME" && n.Param.Value != "XDG_CONFIG_HOME" {
					if _, ok := a.env[n.Param.Value]; !ok {
						return true
					}
				}
			}
		}
	}
	return false
}

// writeProtected applies the same configuration target rule as file tools and patches.
func (a *analyzer) writeProtected(name, cwd string) bool {
	if !a.staticWriteTarget(name, cwd) {
		return true
	}
	return a.configPath(name, cwd)
}

func (a *analyzer) configPath(name, cwd string) bool {
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if inline, ok := a.env["XDG_CONFIG_HOME"]; ok {
		xdg = inline
	}
	global := os.Getenv("GIT_CONFIG_GLOBAL")
	if inline, ok := a.env["GIT_CONFIG_GLOBAL"]; ok {
		global = inline
	}
	gitDir := a.env["GIT_DIR"]
	if gitDir != "" {
		resolved := paths.Resolve(gitDir, cwd, "", a.home)
		target := paths.Resolve(name, cwd, "", a.home)
		if target == resolved || strings.HasPrefix(target, resolved+string(os.PathSeparator)) {
			return true
		}
	}
	return paths.ConfigWriteProtected(name, cwd, "", a.home, xdg, global)
}

func readOnlyConfigCommand(name string, args []string) bool {
	if name == "git" {
		return true
	}
	if name == "jq" {
		for _, v := range args {
			if v == "-i" || v == "--in-place" {
				return false
			}
		}
		return true
	}
	if name == "find" {
		for _, v := range args {
			if v == "-delete" || v == "-exec" || v == "-execdir" || v == "-ok" || v == "-okdir" || v == "-fprint" {
				return false
			}
		}
		return true
	}
	return strings.Contains(" cat head tail less more ls stat file wc grep rg diff cmp ", " "+name+" ")
}

// Non-read-only commands cannot even name a Git configuration file.
func (a *analyzer) configArgument(name string, args []string, cwd string) bool {
	if readOnlyConfigCommand(name, args) {
		return false
	}
	for _, v := range args {
		if v == "" || v == "-" {
			continue
		}
		values := []string{v}
		if strings.HasPrefix(v, "-") && strings.Contains(v, "=") {
			_, val, _ := strings.Cut(v, "=")
			values = append(values, val)
		}
		if strings.HasPrefix(v, "-t") && len(v) > 2 {
			values = append(values, v[2:])
		}
		if strings.HasPrefix(v, "-C") && len(v) > 2 {
			values = append(values, v[2:])
		}
		for _, value := range values {
			if value == "" || strings.ContainsAny(value, "; \n\t") {
				continue
			}
			if strings.ContainsAny(value, "*?[]$`") || strings.HasPrefix(value, "-") {
				continue
			}
			if a.configPath(value, cwd) {
				a.reason = "git configuration write target"
				return true
			}
		}
	}
	return false
}

// writeCommand checks known output roles before generic reader classification.
func (a *analyzer) writeCommand(name string, args []string, cwd string) bool {
	target := func(value string) bool {
		if a.writeProtected(value, cwd) {
			a.reason = "git configuration write target"
			return true
		}
		return false
	}
	switch name {
	case "tee", "touch", "truncate", "vim", "vi", "nvim", "nano", "micro", "hx", "kak", "code", "codium", "subl", "mate", "emacs", "emacsclient", "ex", "mkdir":
		for _, arg := range args {
			if !strings.HasPrefix(arg, "-") && target(arg) {
				return true
			}
		}
	case "cp", "mv", "ln", "install", "rsync":
		for i, arg := range args {
			if (arg == "-t" || arg == "--target-directory") && i+1 < len(args) && target(args[i+1]) {
				return true
			}
			if strings.HasPrefix(arg, "-t") && len(arg) > 2 && target(arg[2:]) {
				return true
			}
			if strings.HasPrefix(arg, "--target-directory=") && target(strings.TrimPrefix(arg, "--target-directory=")) {
				return true
			}
		}
		if len(args) > 1 && target(args[len(args)-1]) {
			return true
		}
	case "dd":
		for _, arg := range args {
			if strings.HasPrefix(arg, "of=") && target(strings.TrimPrefix(arg, "of=")) {
				return true
			}
		}
	case "sed", "perl":
		inplace := false
		for _, arg := range args {
			if arg == "-i" || strings.HasPrefix(arg, "-i") || arg == "--in-place" || strings.HasPrefix(arg, "--in-place=") || name == "sed" && (strings.HasPrefix(arg, "-E") || strings.HasPrefix(arg, "-n")) && strings.Contains(arg, "i") || name == "perl" && strings.HasPrefix(arg, "-p") && strings.Contains(arg, "i") {
				inplace = true
			}
		}
		if inplace {
			for _, arg := range args {
				if !strings.HasPrefix(arg, "-") && target(arg) {
					return true
				}
			}
		}
	}
	return false
}

// staticVariable resolves only literal assignments made in this command and
// the two explicitly permitted home locations from the hook environment.
func (a *analyzer) staticVariable(name string) (string, bool) {
	if name == "HOME" {
		return a.home, a.home != ""
	}
	value, ok := a.env[name]
	if !ok && name == "XDG_CONFIG_HOME" {
		value, ok = os.LookupEnv(name)
	}
	return value, ok && value != "" && !strings.ContainsAny(value, "$`*?[]")
}

// writePatternWord catches unquoted globs before the command's argv expansion
// loses the pattern by enumerating existing files.
func writePatternWord(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		if lit, ok := part.(*syntax.Lit); ok && strings.ContainsAny(lit.Value, "*?[") {
			return true
		}
	}
	return false
}

func writePatternCommand(name string, args []*syntax.Word) bool {
	if len(args) < 2 {
		return false
	}
	switch name {
	case "tee", "touch", "truncate", "mkdir", "vim", "vi", "nvim", "nano", "micro", "hx", "kak", "code", "codium", "subl", "mate", "emacs", "emacsclient", "ex":
		for _, w := range args[1:] {
			if writePatternWord(w) {
				return true
			}
		}
	case "cp", "mv", "ln", "install", "rsync":
		return writePatternWord(args[len(args)-1])
	case "sed", "perl":
		inplace := false
		for _, w := range args[1:] {
			if v := literal(w); v == "-i" || strings.HasPrefix(v, "-i") || v == "--in-place" || strings.HasPrefix(v, "--in-place=") || name == "perl" && strings.HasPrefix(v, "-p") && strings.Contains(v, "i") {
				inplace = true
			}
		}
		if inplace {
			for _, w := range args[1:] {
				if writePatternWord(w) {
					return true
				}
			}
		}
	}
	return false
}
