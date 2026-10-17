package policy

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/avhn/secret/internal/hook/roles"
)

// Normalize curl's file-input operands before applying the ordinary metadata
// classifier. Payloads, form-string values and output destinations stay data.
func (a *analyzer) curlInputs(args []string, depth int, cwd string) bool {
	var unknown []string
	input := func(name string) bool {
		if name != "" && name != "-" && a.inputProtected(name, cwd) {
			a.reason = roles.FileInput
			return true
		}
		return false
	}
	fileURL := func(value string) bool {
		name, local, valid := curlFileURLPath(value)
		if !local {
			return false
		}
		if !valid {
			a.reason = roles.Indeterminate
			return true
		}
		return input(name)
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if fileURL(arg) {
			return true
		}
		key, value, attached := strings.Cut(arg, "=")
		kind := ""
		switch key {
		case "--data", "--data-ascii", "--data-binary", "--json", "--header", "--write-out":
			kind = "at"
		case "--data-urlencode":
			kind = "urlencode"
		case "--form":
			kind = "form"
		case "--upload-file", "--config":
			kind = "file"
		case "--url":
			kind = "url"
		case "--output", "--data-raw", "--form-string", "--user", "--user-agent", "--proxy", "--request":
			kind = "data"
		}
		if kind == "" && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			// Known value-taking short options end their cluster; their suffix
			// is the value, not a set of additional switches.
			for j := 1; j < len(arg); j++ {
				switch arg[j] {
				case 'd', 'H', 'w':
					kind = "at"
				case 'F':
					kind = "form"
				case 'T', 'K':
					kind = "file"
				case 'o', 'u', 'x', 'X', 'A', 'e':
					kind = "data"
				}
				if kind != "" {
					value, attached = arg[j+1:], j+1 < len(arg)
					break
				}
			}
		}
		if kind == "" {
			unknown = append(unknown, arg)
			continue
		}
		if !attached {
			i++
			if i >= len(args) {
				a.reason = roles.Indeterminate
				return true
			}
			value = args[i]
		}
		switch kind {
		case "url":
			if fileURL(value) {
				return true
			}
		case "file":
			if input(value) {
				return true
			}
		case "at":
			if strings.HasPrefix(value, "@") && input(value[1:]) {
				return true
			}
		case "urlencode":
			if name, file, ok := strings.Cut(value, "@"); ok && !strings.Contains(name, "=") && input(file) {
				return true
			}
		case "form":
			_, value, _ = strings.Cut(value, "=")
			files, known := curlFormFiles(value)
			if !known {
				a.reason = roles.Indeterminate
				return true
			}
			for _, file := range files {
				if input(file) {
					return true
				}
			}
		}
	}
	// Unknown options keep the generic positive-witness checks. A recognized
	// payload or output option above must not be reinterpreted as shell code.
	for _, arg := range unknown {
		if !strings.HasPrefix(arg, "https://") && !strings.HasPrefix(arg, "http://") && hasProtectedLiteral(arg) {
			a.reason = roles.FileInput
			return true
		}
	}
	a.unknownExecution(unknown, depth, cwd)
	return a.reason != ""
}

// curlFileURLPath removes URL query/fragment syntax before classifying a local
// path. Drive-letter URLs without a slash after file: are opaque to net/url,
// so their path needs the same unescaping as an ordinary hierarchical URL.
func curlFileURLPath(value string) (name string, local, valid bool) {
	if !strings.HasPrefix(strings.ToLower(value), "file:") {
		return "", false, true
	}
	u, err := url.Parse(value)
	if err != nil || u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		return "", true, false
	}
	name = u.Path
	if u.Opaque != "" {
		name, err = url.PathUnescape(u.Opaque)
		if err != nil {
			return "", true, false
		}
	}
	for _, ch := range name {
		if ch < 0x20 || ch == 0x7f {
			return "", true, false
		}
	}
	name = filepath.FromSlash(name)
	// A URL's leading slash is not part of a Windows drive volume. Let the
	// host's filepath rules identify volumes rather than treating /C:/ as a
	// drive path on Unix, where it names an ordinary absolute directory.
	if len(name) > 1 && os.IsPathSeparator(name[0]) && filepath.VolumeName(name[1:]) != "" {
		name = name[1:]
	}
	return name, true, true
}

// Curl quotes commas and semicolons inside form filenames independently of the
// shell. Metadata such as filename= is data, but headers=@ names another input.
func curlFormFiles(value string) ([]string, bool) {
	var files []string
	var token strings.Builder
	quoted, metadata := false, false
	fileBody := strings.HasPrefix(value, "@") || strings.HasPrefix(value, "<")
	if fileBody {
		value = value[1:]
	} else {
		// Literal content is not a quoted filename list. Its commas and
		// quotes are payload; only the semicolon introduces form metadata.
		_, value, metadata = strings.Cut(value, ";")
		if !metadata {
			return nil, true
		}
	}
	flush := func() bool {
		part := token.String()
		token.Reset()
		if !metadata && fileBody {
			if part == "" {
				return false
			}
			files = append(files, part)
		} else if metadata && strings.HasPrefix(part, "headers=@") {
			files = append(files, strings.TrimPrefix(part, "headers=@"))
		}
		return true
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\\' && quoted && i+1 < len(value) && (value[i+1] == '\\' || value[i+1] == '"') {
			i++
			token.WriteByte(value[i])
			continue
		}
		if ch == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && (ch == ';' || ch == ',' && fileBody && !metadata) {
			if !flush() {
				return nil, false
			}
			metadata = ch == ';'
			continue
		}
		token.WriteByte(ch)
	}
	if quoted || !flush() {
		return nil, false
	}
	return files, true
}
