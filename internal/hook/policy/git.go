package policy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
	"mvdan.cc/sh/v3/syntax"
)

func gitShellEnv(key string) bool {
	return optionIn("GIT_EXTERNAL_DIFF GIT_EDITOR GIT_SEQUENCE_EDITOR GIT_PAGER GIT_SSH GIT_SSH_COMMAND GIT_ASKPASS GIT_PROXY_COMMAND GIT_EXEC_PATH EDITOR VISUAL PAGER", key)
}

// shellValue checks literal command text without expanding or executing it.
func (a *analyzer) shellValue(value string, depth int, cwd string) {
	if value == "" {
		a.reason = roles.Indeterminate
		return
	}
	a.fragmentAt(value, depth+1, cwd)
	if a.uncertain {
		a.reason = roles.Indeterminate
	}
}

func gitCommandKey(key string) bool {
	key = strings.ToLower(key)
	if strings.HasPrefix(key, "alias.") || strings.HasPrefix(key, "pager.") || strings.HasPrefix(key, "includeif.") || key == "include.path" {
		return true
	}
	if optionIn("core.pager core.editor core.sshcommand core.fsmonitor core.hookspath core.askpass diff.external sequence.editor credential.helper gpg.program uploadpack.packobjectshook", key) {
		return true
	}
	for _, group := range []struct{ prefix, suffixes string }{
		{"diff.", "command textconv"}, {"filter.", "clean smudge process"}, {"merge.", "driver"}, {"gpg.", "program"},
	} {
		if strings.HasPrefix(key, group.prefix) {
			for _, suffix := range strings.Fields(group.suffixes) {
				if strings.HasSuffix(key, "."+suffix) {
					return true
				}
			}
		}
	}
	return false
}

// gitConfig checks inline configuration against the inert-key allowlist.
func gitConfigInert(key, value string) bool {
	if strings.HasPrefix(key, "pager.") {
		return strings.EqualFold(value, "true") || strings.EqualFold(value, "false")
	}
	for _, prefix := range []string{"color.", "advice.", "log.", "column.", "i18n."} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return optionIn("core.quotepath core.autocrlf core.safecrlf core.abbrev user.name user.email init.defaultbranch format.pretty safe.directory http.sslverify", key)
}

func (a *analyzer) gitConfig(config string, aliases map[string]string, depth int, cwd string) {
	key, value, ok := strings.Cut(config, "=")
	key = strings.ToLower(key)
	if !ok || key == "" {
		a.reason = roles.Indeterminate
		return
	}
	if !strings.ContainsAny(value, " \t\n") && a.inputProtected(value, cwd) {
		a.reason = roles.FileInput
		return
	}
	if gitConfigInert(key, value) {
		return
	}
	if strings.HasPrefix(key, "url.") || strings.HasPrefix(key, "protocol.") || key == "core.gitproxy" || strings.HasPrefix(key, "remote.") && (strings.HasSuffix(key, ".url") && strings.HasPrefix(value, "ext::")) {
		a.reason = roles.Indeterminate
		return
	}
	if !gitCommandKey(key) {
		// Unmodeled keys may name an executable or redirect a transport.
		a.reason = roles.Indeterminate
		return
	}
	if strings.HasPrefix(key, "include") || key == "core.hookspath" {
		// A config or hooks directory cannot be certified without reading code.
		a.reason = roles.Indeterminate
		return
	}
	if strings.HasPrefix(key, "alias.") {
		if strings.HasPrefix(value, "!") {
			a.shellValue(value[1:], depth, cwd)
		}
		aliases[strings.TrimPrefix(key, "alias.")] = value
		return
	}
	if key == "credential.helper" && strings.HasPrefix(value, "!") {
		value = value[1:]
	}
	a.shellValue(value, depth, cwd)
}

// gitCommand owns all Git dispatch: no legacy reader shortcut runs afterwards.
func (a *analyzer) gitCommand(args []string, depth int, cwd string, direct bool) {
	if depth > 4 {
		a.reason = roles.Indeterminate
		return
	}
	aliases := make(map[string]string)
	if a.env == nil {
		a.env = make(map[string]string)
	}
	for _, key := range []string{"GIT_DIR", "GIT_WORK_TREE"} {
		if _, known := a.env[key]; !known {
			if value, present := os.LookupEnv(key); present {
				a.env[key] = value
			}
		}
	}
	// Inherited editor/pager commands are user configuration, not command text.
	// Only assignments recorded by hookAssignment are analyzed as shell text.
	if _, known := a.env["GIT_EXEC_PATH"]; !known {
		if _, present := os.LookupEnv("GIT_EXEC_PATH"); present {
			a.reason = roles.Indeterminate
			return
		}
	}
	repoUncertain := false
	for _, key := range strings.Fields("GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE") {
		if _, present := a.env[key]; present {
			repoUncertain = true
		} else if _, present := os.LookupEnv(key); present {
			repoUncertain = true
		}
	}
	for _, key := range strings.Fields("GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_CONFIG GIT_INDEX_FILE GIT_COMMON_DIR") {
		if key != "GIT_CONFIG_COUNT" {
			if _, known := a.env[key]; !known {
				if _, present := os.LookupEnv(key); present {
					a.reason = roles.Indeterminate
					return
				}
			}
			if _, present := a.env[key]; present {
				a.reason = roles.Indeterminate
				return
			}
		}
	}
	gitDir, workTree := "", ""
	bareGlobal := false
	if value, ok := a.env["GIT_DIR"]; ok {
		if !staticGitPath(value) {
			a.reason = roles.Indeterminate
			return
		}
		gitDir = value
	}
	if value, ok := a.env["GIT_WORK_TREE"]; ok {
		if !staticGitPath(value) {
			a.reason = roles.Indeterminate
			return
		}
		workTree = value
	}
	countValue, countPresent := a.env["GIT_CONFIG_COUNT"]
	if !countPresent {
		countValue, countPresent = os.LookupEnv("GIT_CONFIG_COUNT")
	}
	if countPresent {
		count, err := strconv.Atoi(countValue)
		if err != nil || count < 0 || count > 128 {
			a.reason = roles.Indeterminate
			return
		}
		for n := 0; n < count; n++ {
			key, hasKey := a.env["GIT_CONFIG_KEY_"+strconv.Itoa(n)]
			val, hasValue := a.env["GIT_CONFIG_VALUE_"+strconv.Itoa(n)]
			if !hasKey {
				key, hasKey = os.LookupEnv("GIT_CONFIG_KEY_" + strconv.Itoa(n))
			}
			if !hasValue {
				val, hasValue = os.LookupEnv("GIT_CONFIG_VALUE_" + strconv.Itoa(n))
			}
			if !hasKey || !hasValue {
				a.reason = roles.Indeterminate
				return
			}
			a.gitConfig(key+"="+val, aliases, depth, cwd)
		}
	}
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		arg := args[0]
		args = args[1:]
		key, value, attached := strings.Cut(arg, "=")
		if len(arg) > 2 && key != "-C" && key != "-c" && (strings.HasPrefix(arg, "-C") || strings.HasPrefix(arg, "-c")) {
			key, value, attached = arg[:2], arg[2:], true
		}
		if optionIn("-C -c --config-env --git-dir --work-tree --namespace --attr-source --exec-path --super-prefix --list-cmds", key) {
			if !attached {
				if len(args) == 0 {
					a.reason = roles.Indeterminate
					return
				}
				value, args = args[0], args[1:]
			}
			switch key {
			case "-C":
				if !staticGitPath(value) {
					a.reason = roles.Indeterminate
					return
				}
				cwd = a.gitPath(value, cwd)
			case "--git-dir":
				if !staticGitPath(value) {
					a.reason = roles.Indeterminate
					return
				}
				gitDir = value
			case "--work-tree":
				if !staticGitPath(value) {
					a.reason = roles.Indeterminate
					return
				}
				workTree = value
			case "-c":
				a.gitConfig(value, aliases, depth, cwd)
			case "--config-env":
				// Git splits name=ENVVAR at the last equals sign; names may contain one.
				cut := strings.LastIndex(value, "=")
				ok := cut > 0
				configKey, envKey := value, ""
				if ok {
					configKey, envKey = value[:cut], value[cut+1:]
				}
				val, known := a.env[envKey]
				if !known {
					val, known = os.LookupEnv(envKey)
				}
				if !ok || !known {
					a.reason = roles.Indeterminate
					return
				}
				a.gitConfig(configKey+"="+val, aliases, depth, cwd)
			case "--exec-path":
				a.reason = roles.Indeterminate
				return
			}
		} else if !optionIn("--no-pager -p --paginate --bare --literal-pathspecs --glob-pathspecs --noglob-pathspecs --icase-pathspecs --no-optional-locks --no-replace-objects --no-lazy-fetch", key) || attached {
			a.reason = roles.Indeterminate
			return
		} else if key == "--bare" {
			bareGlobal = true
			if gitDir == "" {
				gitDir = a.gitPath(".", cwd)
			}
		}
	}
	if a.reason != "" || len(args) == 0 {
		return
	}
	configAliases, err := gitAliases(resolveGitDirectory(cwd, gitDir), cwd, a.home, a.env)
	if err != nil {
		a.reason = roles.Indeterminate
		return
	}
	for key, value := range aliases {
		configAliases[key] = value // Inline configuration takes precedence.
	}
	for n := 0; ; n++ {
		value, ok := configAliases[args[0]]
		if !ok {
			break
		}
		if strings.HasPrefix(value, "!") {
			a.reason = roles.Indeterminate
			return
		}
		if n >= 4 {
			a.reason = roles.Indeterminate
			return
		}
		file, err := syntax.NewParser().Parse(strings.NewReader(value), "")
		if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
			a.reason = roles.Indeterminate
			return
		}
		call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
		if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
			a.reason = roles.Indeterminate
			return
		}
		expanded := []string{}
		for _, word := range call.Args {
			values, ok := a.expandWord(word, cwd)
			if !ok {
				a.reason = roles.Indeterminate
				return
			}
			expanded = append(expanded, values...)
		}
		if len(expanded) == 0 || strings.HasPrefix(expanded[0], "-") || strings.HasPrefix(expanded[0], "!") {
			a.reason = roles.Indeterminate
			return
		}
		args = append(expanded, args[1:]...)
	}
	sub, operands := args[0], args[1:]
	for _, operand := range operands {
		if strings.Contains(strings.ToLower(operand), "ext::") {
			a.reason = roles.Indeterminate
			return
		}
	}
	// Credential access remains prohibited even in an empty repository.
	if sub == "credential" && len(operands) == 1 && operands[0] == "fill" && direct {
		return
	}
	if sub == "credential" || sub == "credential-cache" || sub == "credential-store" {
		a.reason = roles.Printer
		return
	}
	for i, arg := range operands {
		key, value, attached := strings.Cut(arg, "=")
		shell := optionIn("--upload-pack --receive-pack --exec", key) || sub == "rebase" && key == "-x" || sub == "difftool" && optionIn("-x --extcmd", key) || sub == "mergetool" && key == "-c"
		if !shell && len(arg) > 2 && ((sub == "rebase" || sub == "difftool") && strings.HasPrefix(arg, "-x") || sub == "mergetool" && strings.HasPrefix(arg, "-c")) {
			shell, attached, value = true, true, arg[2:]
		}
		if shell {
			if !attached {
				if i+1 >= len(operands) {
					a.reason = roles.Indeterminate
					return
				}
				value = operands[i+1]
			}
			a.shellValue(value, depth, cwd)
		}
	}
	if sub == "filter-branch" || sub == "bisect" && len(operands) > 0 && operands[0] == "run" || sub == "submodule" && len(operands) > 0 && operands[0] == "foreach" {
		// These interpret argument lists in multiple execution contexts.
		a.reason = roles.Indeterminate
		return
	}
	if a.reason != "" {
		return
	}
	operandCWD := cwd
	if workTree != "" {
		operandCWD = a.gitPath(workTree, cwd)
	}
	if a.gitSafe(sub, operands, cwd) {
		if operandCWD != cwd {
			a.gitSafe(sub, operands, operandCWD)
		}
		return
	}
	if a.reason != "" {
		return
	}
	if repoUncertain || bareGlobal {
		a.reason = roles.Indeterminate
		return
	}
	for _, arg := range operands {
		_, value, attached := strings.Cut(arg, "=")
		if attached && strings.HasPrefix(arg, "-") {
			arg = value
		}
		if paths.LexicalProtected(arg, cwd, a.home) || a.inputProtected(arg, cwd) || a.inputProtected(arg, operandCWD) {
			a.reason = roles.FileInput
			return
		}
		if _, member, ok := strings.Cut(arg, ":"); ok && paths.LexicalProtected(member, cwd, a.home) {
			a.reason = roles.FileInput
			return
		}
	}
	if gitDir != "" {
		gitDir = a.gitPath(gitDir, cwd)
	}
	if workTree != "" {
		workTree = a.gitPath(workTree, cwd)
		if gitDir == "" && indexProtected(resolveGitDirectory(workTree, ""), a.home) {
			a.reason = roles.FileInput
			return
		}
	}
	if indexProtected(resolveGitDirectory(cwd, gitDir), a.home) {
		a.reason = roles.FileInput
	}
}

func staticGitPath(value string) bool {
	return value != "" && !strings.ContainsAny(value, "$`*?[]~\x00\r\n")
}

type gitOptions struct{ flags, values, optional string }

// Every accepted option has an explicit arity. Unknown options classify the
// whole form as content-producing, rather than silently skipping a value.
var gitSafeOptions = map[string]gitOptions{
	"status":       {"-s --short -b --branch --porcelain --long --show-stash --ahead-behind --no-ahead-behind -z --ignored", "--untracked-files --ignore-submodules --column", "--porcelain --ignored --untracked-files"},
	"log":          {"--oneline --graph --all-match -i --stat --shortstat --numstat --name-only --name-status --all --reverse --first-parent --merges --no-merges --follow --no-color", "-n --max-count --skip --since --until --after --before --author --committer --grep --format --pretty --date", "--decorate --abbrev --abbrev-commit --no-abbrev-commit --branches --tags --remotes --color --stat"},
	"shortlog":     {"--oneline --all --reverse --no-merges -s -n -e", "--format --pretty --author --committer --grep --since --until --max-count", "--branches --tags --remotes"},
	"diff":         {"--stat --name-only --name-status --numstat --shortstat --quiet --exit-code --cached --staged --no-color", "", "--stat"},
	"branch":       {"--list -l -a --all -r --remotes --show-current", "--sort --format --contains --no-contains --merged --no-merged", "--color"},
	"tag":          {"--list -l -n", "--sort --format --contains --no-contains --merged --no-merged", "--color"},
	"remote":       {"-v --verbose", "", ""},
	"rev-parse":    {"--verify --quiet -q --show-toplevel --show-prefix --show-cdup --git-dir --absolute-git-dir --is-inside-work-tree --is-bare-repository --short --symbolic --symbolic-full-name --abbrev-ref --all", "", "--short --abbrev-ref"},
	"rev-list":     {"--all --count --first-parent --merges --no-merges --reverse --left-right --boundary --no-walk", "-n --max-count --since --until", ""},
	"ls-files":     {"-z -c --cached -d --deleted -m --modified -o --others -i --ignored -s --stage -u --unmerged -k --killed --exclude-standard --full-name --error-unmatch --deduplicate", "-x --exclude --exclude-from --exclude-per-directory --format", ""},
	"ls-tree":      {"-r -d -t -z --name-only --name-status --full-name --full-tree -l --long", "--format", "--abbrev"},
	"show-ref":     {"--head --heads --tags --verify --quiet -q --dereference -d --hash -s", "", "--abbrev"},
	"symbolic-ref": {"-q --quiet --short", "", ""},
	"merge-base":   {"--all -a --octopus --independent --is-ancestor --fork-point", "", ""},
	"describe":     {"--all --tags --contains --always --long --first-parent", "--match --exclude --abbrev --candidates", "--dirty --broken"},
	"add":          {"-A --all -u --update -f --force -n --dry-run -v --verbose -N --intent-to-add --ignore-errors --ignore-missing --renormalize", "", ""},
	"commit":       {"-a --all --amend --no-edit --allow-empty --allow-empty-message -q --quiet -n --no-verify -s --signoff --reset-author", "-m --message -F --file --author --date --cleanup --reuse-message -C --reedit-message -c", "-S --gpg-sign"},
	"restore":      {"--staged --worktree -W -S --ours --theirs --ignore-unmerged --overlay --no-overlay", "-s --source", ""},
	"checkout":     {"-f --force -q --quiet --ours --theirs --detach --track --no-track", "-b -B --orphan", ""},
	"switch":       {"--detach -d -f --force --discard-changes --merge -m --guess --no-guess --track --no-track", "-c -C --create --force-create", ""},
	"stash":        {"-q --quiet -u --include-untracked -a --all --keep-index --no-keep-index --index --staged", "-m --message", ""},
	"fetch":        {"--all --prune -p --tags -t --no-tags -q --quiet -v --verbose --dry-run --force -f", "--depth --deepen --shallow-since --shallow-exclude", "--recurse-submodules"},
	"pull":         {"--ff --ff-only --no-ff --rebase --no-rebase --no-edit -q --quiet --all --prune", "--depth", "--rebase"},
	"push":         {"--all --tags --delete -d --force -f --force-with-lease --dry-run -n -u --set-upstream --porcelain -q --quiet", "--repo", "--force-with-lease"},
	"clone":        {"--bare --mirror --quiet -q --no-checkout -n --single-branch --no-single-branch --recurse-submodules", "--depth --branch -b --origin -o --filter --reference", "--recurse-submodules"},
	"init":         {"--bare --quiet -q", "-b --initial-branch --template --separate-git-dir --object-format", "--shared"},
	"merge":        {"--ff --ff-only --no-ff --no-edit --no-commit --commit --abort --continue --squash --quit --allow-unrelated-histories", "-m --message -s --strategy -X --strategy-option", ""},
	"rebase":       {"--abort --continue --skip --quit --autostash --no-autostash --keep-base --root --no-rebase-merges", "--onto --strategy -s --strategy-option -X", "--rebase-merges"},
	"cherry-pick":  {"--abort --continue --skip --quit --no-commit -n --signoff -s -x --ff", "-m --mainline --strategy --strategy-option -X", ""},
	"revert":       {"--abort --continue --skip --quit --no-commit -n --no-edit", "-m --mainline --strategy --strategy-option -X", ""},
	"reset":        {"--soft --mixed --hard --merge --keep -q --quiet", "", ""},
	"rm":           {"-f --force -r --cached -n --dry-run --ignore-unmatch -q --quiet", "", ""},
	"mv":           {"-f --force -k -n --dry-run -v --verbose", "", ""},
	"worktree":     {"--porcelain --force -f --detach --lock --unlock", "-b -B --reason", ""},
	"gc":           {"--aggressive --auto --quiet --no-prune", "", "--prune"},
	"prune":        {"-n --dry-run -v --verbose --progress", "--expire", ""},
	"blame":        {"--line-porcelain --porcelain -p --incremental --show-name --show-number -n -f -s -e --show-email -w", "-L --date", "--abbrev"},
	"check-ignore": {"-q --quiet -v --verbose -n --non-matching -z --no-index", "", ""},
}

func (a *analyzer) gitSafe(sub string, args []string, cwd string) bool {
	if sub == "config" {
		// A whole-config listing cannot certify that credentials are absent.
		// Getters accept only modeled non-credential keys, never URL/auth keys.
		if len(args) == 2 && optionIn("--get --get-all", args[0]) && optionIn("user.name user.email core.repositoryformatversion core.filemode core.bare core.logallrefupdates core.ignorecase core.precomposeunicode core.autocrlf core.eol core.symlinks core.abbrev color.ui init.defaultbranch pull.rebase push.default fetch.prune", strings.ToLower(args[1])) {
			return true
		}
		a.reason = roles.Indeterminate
		return false
	}
	table, ok := gitSafeOptions[sub]
	if !ok {
		return false
	}
	if sub == "remote" {
		for _, arg := range args {
			if arg != "-v" && arg != "--verbose" && arg != "show" {
				return false
			}
		}
	}
	if sub == "stash" {
		if len(args) == 0 {
			return true
		}
		if !optionIn("push save pop apply drop clear list", args[0]) {
			return false
		}
		args = args[1:]
	}
	if sub == "worktree" {
		if len(args) == 0 || !optionIn("add list lock unlock move prune remove repair", args[0]) {
			return false
		}
		args = args[1:]
	}
	summary := false
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			if optionIn("add commit restore checkout switch blame rm mv", sub) && a.inputProtected(arg, cwd) {
				a.reason = roles.FileInput
				return false
			}
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		if sub == "log" && len(arg) > 1 && strings.Trim(arg[1:], "0123456789") == "" {
			continue
		}
		if !attached && !strings.HasPrefix(arg, "--") && len(arg) > 2 && optionIn(table.values, arg[:2]) {
			key, value, attached = arg[:2], arg[2:], true
		}
		if optionIn(table.values, key) {
			if !attached {
				i++
				if i >= len(args) {
					return false
				}
				value = args[i]
			}
			if optionIn("-F --file --exclude-from", key) && a.inputProtected(value, cwd) {
				a.reason = roles.FileInput
				return false
			}
		} else if optionIn(table.optional, key) {
		} else if !optionIn(table.flags, key) || attached {
			return false
		}
		if sub == "diff" && optionIn("--stat --name-only --name-status --numstat --shortstat --quiet --exit-code", key) {
			summary = true
		}
	}
	return sub != "diff" || summary
}

// Git repository locations cross from shell text into native filesystem paths.
func (a *analyzer) gitPath(value, cwd string) string {
	if filepath.IsAbs(value) {
		return value
	}
	if cwd == "" {
		return ""
	}
	return paths.Resolve(value, cwd, "", a.home)
}
