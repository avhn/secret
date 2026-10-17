package policy

import (
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

// Include the GNU long-option namespace when resolving prefixes, even options
// whose behavior is not modeled. Recognition alone never grants permission.
const tarLongOptions = "absolute-names across-filesystems add-file after-date anchored atime-preserve auto-compress backup blocking-factor bzip2 catenate checkpoint checkpoint-action check-device check-links compress concatenate confirmation create delay-directory-restore delete dereference diff directory exclude exclude-backups exclude-caches exclude-caches-all exclude-caches-under exclude-from exclude-ignore exclude-ignore-recursive exclude-tag exclude-tag-all exclude-tag-under exclude-vcs exclude-vcs-ignores extract file files-from force-local format full-time get group group-map gzip hard-dereference help hole-detection ignore-case ignore-command-error ignore-failed-read ignore-zeros incremental index-file info-script interactive keep-directory-symlink keep-newer-files keep-old-files label level listed-incremental list lzip lzma lzop mode mtime multi-volume new-volume-script newer newer-mtime no-acls no-anchored no-auto-compress no-check-device no-delay-directory-restore no-ignore-case no-ignore-command-error no-null no-overwrite-dir no-quote-chars no-recursion no-same-owner no-same-permissions no-seek no-selinux no-unquote no-verbatim-files-from no-wildcards no-wildcards-match-slash no-xattrs null numeric-owner occurance occurrence old-archive one-file-system one-top-level overwrite overwrite-dir owner owner-map pax-option portability posix preserve-order preserve-permissions quote-chars quoting-style read-full-records record-size recursive-unlink recursion remove-files restrict rmt-command rsh-command same-order same-owner same-permissions seek selinux show-defaults show-omitted-dirs show-snapshot-field show-transformed-names show-stored-names skip-old-files sort sparse sparse-version starting-file strip-components suffix tape-length test-label to-command to-stdout totals touch transform uncompress ungzip unlink-first unquote update usage use-compress-program utc verbose verify version volno-file warning wildcards wildcards-match-slash xattrs xattrs-exclude xattrs-include xz zstd"

func uniqueOption(key, table string) string {
	match := ""
	for _, name := range strings.Fields(table) {
		if name == key {
			return name
		}
		if key != "" && strings.HasPrefix(name, key) {
			if match != "" {
				return ""
			}
			match = name
		}
	}
	return match
}

func (a *analyzer) archiveCommand(name string, args []string, depth int, cwd string) {
	if name == "gtar" {
		name = "tar"
	}
	if name == "unzip" {
		a.unzipCommand(args, cwd)
		return
	}
	if name == "7z" || name == "7za" || name == "cpio" {
		// Only listing is modeled for these formats. Extraction has implicit inputs.
		if len(args) == 0 {
			a.reason = roles.Indeterminate
			return
		}
		listing := name != "cpio" && args[0] == "l"
		for _, v := range args {
			if name == "cpio" && (v == "-t" || v == "--list" || v == "-it") {
				listing = true
				continue
			}
			if strings.HasPrefix(v, "-") && !optionIn("-v --verbose -t --list -it", v) && !(name != "cpio" && strings.HasPrefix(v, "-o")) {
				a.reason = roles.Indeterminate
				return
			}
			if a.inputProtected(v, cwd) {
				a.reason = roles.FileInput
				return
			}
		}
		if !listing && name == "cpio" {
			a.reason = roles.Indeterminate
		}
		return
	}
	type operand struct{ name, cwd string }
	var inputs []operand
	mode := ""
	options := true
	archive := ""
	setMode := func(next string) {
		if mode != "" && mode != next {
			a.reason = roles.Indeterminate
		}
		mode = next
	}
	consume := func(i *int, value string, attached bool) string {
		if attached {
			return value
		}
		*i++
		if *i >= len(args) {
			a.reason = roles.Indeterminate
			return ""
		}
		return args[*i]
	}
	handle := func(key, value string) {
		switch key {
		case "create":
			setMode("create")
		case "extract", "get":
			setMode("extract")
		case "list":
			setMode("list")
		case "to-stdout", "to-command":
			a.reason = roles.Indeterminate
		case "file":
			archive = value
		case "directory":
			cwd = a.resolve(value, cwd)
		case "add-file":
			inputs = append(inputs, operand{value, cwd})
		case "files-from":
			a.reason = roles.Indeterminate
		case "exclude-from":
			if a.inputProtected(value, cwd) {
				a.reason = roles.FileInput
			}
		case "checkpoint-action":
			if strings.HasPrefix(value, "exec=") {
				a.shellValue(strings.TrimPrefix(value, "exec="), depth, cwd)
			} else {
				a.reason = roles.Indeterminate
			}
		case "use-compress-program", "rsh-command", "info-script", "new-volume-script":
			a.shellValue(value, depth, cwd)
		}
	}
	const flags = "create extract get list dereference hard-dereference verbose gzip bzip2 xz zstd auto-compress numeric-owner wildcards wildcards-match-slash no-wildcards no-wildcards-match-slash anchored no-anchored ignore-case no-ignore-case no-same-owner no-same-permissions preserve-permissions same-permissions touch keep-old-files skip-old-files overwrite no-overwrite-dir recursion no-recursion one-file-system null no-null to-stdout"
	const values = "file directory add-file exclude exclude-from files-from transform strip-components blocking-factor format label suffix checkpoint-action use-compress-program rsh-command info-script new-volume-script to-command"
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			key, value, attached := strings.Cut(arg[2:], "=")
			key = uniqueOption(key, tarLongOptions)
			if optionIn(values, key) {
				value = consume(&i, value, attached)
			} else if !optionIn(flags, key) || attached {
				a.reason = roles.Indeterminate
				return
			}
			handle(key, value)
		} else if options && (strings.HasPrefix(arg, "-") && arg != "-" || i == 0 && !strings.ContainsAny(arg, "/.") && strings.ContainsAny(arg, "cxt")) {
			old := !strings.HasPrefix(arg, "-")
			cluster := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(cluster); j++ {
				key := ""
				switch cluster[j] {
				case 'c':
					key = "create"
				case 'x':
					key = "extract"
				case 't':
					key = "list"
				case 'O':
					key = "to-stdout"
				case 'h':
					key = "dereference"
				case 'v', 'z', 'j', 'J', 'a', 'p', 'm', 'k':
					continue
				case 'f':
					key = "file"
				case 'C':
					key = "directory"
				case 'T':
					key = "files-from"
				case 'X':
					key = "exclude-from"
				case 'I':
					key = "use-compress-program"
				case 'F':
					key = "info-script"
				default:
					a.reason = roles.Indeterminate
					return
				}
				value := ""
				if optionIn(values, key) {
					value = consume(&i, cluster[j+1:], !old && j+1 < len(cluster))
					if !old {
						j = len(cluster)
					}
				}
				handle(key, value)
			}
		} else {
			inputs = append(inputs, operand{arg, cwd})
		}
		if a.reason != "" {
			return
		}
	}
	if mode == "" {
		a.reason = roles.Indeterminate
		return
	}
	if mode != "create" && archive != "" && a.inputProtected(archive, cwd) {
		a.reason = roles.FileInput
		return
	}
	if mode == "list" {
		return
	}
	for _, input := range inputs {
		if mode == "create" && a.treeProtectedAll(input.name, input.cwd) || mode == "extract" && (strings.ContainsAny(input.name, "*?[") || paths.LexicalProtected(input.name, input.cwd, a.home)) {
			a.reason = roles.FileInput
			return
		}
	}
}

func (a *analyzer) unzipCommand(args []string, cwd string) {
	listing, options := false, true
	var operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "-d" {
			i++
			if i >= len(args) || a.writeProtected(args[i], cwd) {
				a.reason = roles.Indeterminate
				return
			}
			continue
		}
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if strings.HasPrefix(arg, "--") {
				a.reason = roles.Indeterminate
				return
			}
			for _, flag := range arg[1:] {
				switch flag {
				case 'l', 'Z':
					listing = true
				case 'q', 'v', 'C', '1', '2', 's', 'm', 'h', 't', 'T', 'o':
				case 'p', 'c':
					a.reason = roles.Indeterminate
					return
				default:
					a.reason = roles.Indeterminate
					return
				}
			}
		} else {
			operands = append(operands, arg)
		}
	}
	if len(operands) == 0 {
		a.reason = roles.Indeterminate
		return
	}
	if a.inputProtected(operands[0], cwd) {
		a.reason = roles.FileInput
		return
	}
	if listing {
		return
	}
	for _, member := range operands[1:] {
		if strings.ContainsAny(member, "*?[") || paths.LexicalProtected(member, cwd, a.home) {
			a.reason = roles.FileInput
			return
		}
	}
	// The destination and member operands have already passed the P15 token check.
}
