package policy

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const maxGitConfigBytes = 64 << 10
const maxGitConfigTotal = 512 << 10
const maxGitIncludeDepth = 8

// gitAliases reads bounded configuration in Git precedence order without running
// Git or opening object data. An unreadable or ambiguous config fails closed.
func gitAliases(dir, cwd, home string, env map[string]string) (map[string]string, error) {
	aliases := make(map[string]string)
	total, files := 0, 0
	lookup := func(key string) (string, bool) {
		if value, ok := env[key]; ok {
			return value, true
		}
		return os.LookupEnv(key)
	}
	var read func(string, int) error
	read = func(name string, depth int) error {
		if depth > maxGitIncludeDepth || files >= 64 {
			return os.ErrInvalid
		}
		data, err := boundedMetadata(name, maxGitConfigBytes)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		total += len(data)
		files++
		if total > maxGitConfigTotal {
			return os.ErrInvalid
		}
		// A repeated include may be intentional; the depth limit also catches cycles.
		section, subsection := "", ""
		lines := strings.Split(string(data), "\n")
		for i := 0; i < len(lines); i++ {
			line := lines[i]
			for strings.HasSuffix(line, "\\") && i+1 < len(lines) {
				line = strings.TrimSuffix(line, "\\") + lines[i+1]
				i++
			}
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			if line[0] == '[' {
				if !strings.HasSuffix(line, "]") {
					return os.ErrInvalid
				}
				header := strings.TrimSpace(line[1 : len(line)-1])
				section, subsection = "", ""
				if part, rest, found := strings.Cut(header, " "); found {
					section = strings.ToLower(part)
					rest = strings.TrimSpace(rest)
					if len(rest) < 2 || rest[0] != '"' || rest[len(rest)-1] != '"' {
						return os.ErrInvalid
					}
					subsection = rest[1 : len(rest)-1]
				} else if part, rest, found := strings.Cut(header, "."); found {
					section, subsection = strings.ToLower(part), rest
				} else {
					section = strings.ToLower(header)
				}
				continue
			}
			key, raw, hasValue := strings.Cut(line, "=")
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "" || strings.ContainsAny(key, " \t\r\x00") {
				return os.ErrInvalid
			}
			value := "true"
			if hasValue {
				value, err = gitConfigValue(raw)
				if err != nil {
					return err
				}
			}
			switch section {
			case "alias":
				if subsection != "" {
					return os.ErrInvalid
				}
				aliases[key] = value
			case "include", "includeif":
				if key != "path" {
					continue
				}
				// A conditional include is loaded conservatively: a possibly active
				// alias must never be missed by a static condition approximation.
				target := value
				if strings.HasPrefix(target, "~/") {
					target = filepath.Join(home, target[2:])
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(name), target)
				}
				if target == "" || strings.ContainsAny(target, "\x00\r\n") {
					return os.ErrInvalid
				}
				if err := read(target, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	configPath := func(value string) string {
		if filepath.IsAbs(value) || value == "" {
			return value
		}
		return filepath.Join(cwd, value)
	}
	if disabled, ok := lookup("GIT_CONFIG_NOSYSTEM"); !ok || disabled == "" || disabled == "0" || strings.EqualFold(disabled, "false") || strings.EqualFold(disabled, "no") || strings.EqualFold(disabled, "off") {
		system := filepath.FromSlash("/etc/gitconfig")
		if runtime.GOOS == "windows" {
			// Git for Windows has no fixed system directory. An unknown system
			// config cannot certify a safe alias resolution.
			system = ""
		}
		if value, ok := lookup("GIT_CONFIG_SYSTEM"); ok {
			system = configPath(value)
		}
		if system == "" {
			return nil, os.ErrInvalid
		}
		if err := read(system, 0); err != nil {
			return nil, err
		}
	}
	if global, ok := lookup("GIT_CONFIG_GLOBAL"); ok {
		if global == "" {
			return nil, os.ErrInvalid
		}
		if err := read(configPath(global), 0); err != nil {
			return nil, err
		}
	} else {
		xdg, ok := lookup("XDG_CONFIG_HOME")
		if !ok || xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		for _, file := range []string{filepath.Join(xdg, "git", "config"), filepath.Join(home, ".gitconfig")} {
			if err := read(file, 0); err != nil {
				return nil, err
			}
		}
	}
	if dir != "" {
		for _, file := range []string{"config", "config.worktree"} {
			if err := read(filepath.Join(dir, file), 0); err != nil {
				return nil, err
			}
		}
	}
	return aliases, nil
}

// gitConfigValue decodes Git's double-quoted values, comments and escapes.
// Unknown escapes and unclosed quoting cannot certify an alias.
func gitConfigValue(raw string) (string, error) {
	var out strings.Builder
	quoted, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if escaped {
			switch c {
			case 'n':
				out.WriteByte('\n')
			case 't':
				out.WriteByte('\t')
			case 'b':
				out.WriteByte('\b')
			case '\\', '"', '#', ';':
				out.WriteByte(c)
			default:
				return "", os.ErrInvalid
			}
			escaped = false
		} else if c == '\\' {
			escaped = true
		} else if c == '"' {
			quoted = !quoted
		} else if !quoted && (c == '#' || c == ';') {
			break
		} else {
			out.WriteByte(c)
		}
	}
	if escaped || quoted {
		return "", errors.New("invalid git config quoting")
	}
	return strings.TrimSpace(out.String()), nil
}
