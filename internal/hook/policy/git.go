package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/avhn/secret/internal/hook/paths"
	"github.com/avhn/secret/internal/hook/roles"
)

func gitShellEnv(key string) bool {
	return optionIn("GIT_EXTERNAL_DIFF GIT_EDITOR GIT_SEQUENCE_EDITOR GIT_PAGER GIT_SSH GIT_SSH_COMMAND GIT_ASKPASS SSH_ASKPASS GIT_PROXY_COMMAND GIT_EXEC_PATH EDITOR VISUAL PAGER", key)
}

// editorPagerValue accepts only literal editor or pager commands, never arbitrary shell text.
func (a *analyzer) editorPagerValue(key, value, cwd string) {
	if !optionIn("GIT_EDITOR GIT_SEQUENCE_EDITOR EDITOR VISUAL GIT_PAGER PAGER", key) {
		a.reason = roles.Indeterminate
		return
	}
	if strings.ContainsAny(value, "\r\n") {
		a.reason = roles.Indeterminate
		return
	}
	words := strings.Fields(value)
	if len(words) == 0 || !optionIn("vi vim nvim nano emacs emacsclient code codium subl mate hx kak micro less more most true :", words[0]) && !(optionIn("GIT_PAGER PAGER", key) && optionIn("cat delta", words[0])) {
		a.reason = roles.Indeterminate
		return
	}
	for _, word := range words {
		if strings.ContainsAny(word, "\\'\"$`;&|(){}<>*?[]!\r\n") || a.inputProtected(word, cwd) {
			a.reason = roles.Indeterminate
			return
		}
	}
	if words[0] == "less" && len(words) > 2 {
		// Only one inert flag cluster is accepted for less.
		a.reason = roles.Indeterminate
		return
	}
	for _, option := range words[1:] {
		allowed := false
		switch words[0] {
		case "code", "codium":
			allowed = optionIn("-w --wait -n --new-window -r --reuse-window", option)
		case "subl", "mate":
			allowed = optionIn("-w --wait", option)
		case "emacs", "emacsclient":
			allowed = optionIn("-nw -t -c --no-window-system --tty --create-frame", option)
		case "less":
			allowed = inertLessOption(option)
		}
		if !allowed {
			a.reason = roles.Indeterminate
			return
		}
	}
}

// inertLessOption accepts only a single cluster of flags that cannot load files.
func inertLessOption(option string) bool {
	return len(option) > 1 && option[0] == '-' && strings.Trim(option[1:], "FRXSKNMi-") == ""
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

func (a *analyzer) gitConfig(config string, depth int, cwd string) {
	key, value, ok := strings.Cut(config, "=")
	key = strings.ToLower(key)
	if !ok || key == "" {
		a.reason = roles.Indeterminate
		return
	}
	if !gitConfigInert(key, value) {
		// Every other key may execute code, name a file or redirect a transport.
		a.reason = roles.Indeterminate
		return
	}
	if !strings.ContainsAny(value, " \t\n") && a.inputProtected(value, cwd) {
		a.reason = roles.FileInput
	}
}

// gitCommand owns all Git dispatch: no legacy reader shortcut runs afterwards.
func (a *analyzer) gitCommand(args []string, depth int, cwd string, direct bool) {
	if depth > 4 {
		a.reason = roles.Indeterminate
		return
	}
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
	for _, key := range strings.Fields("GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG GIT_INDEX_FILE GIT_COMMON_DIR") {
		if key != "GIT_CONFIG_COUNT" {
			if _, known := a.env[key]; !known && key != "GIT_CONFIG_GLOBAL" && key != "GIT_CONFIG_SYSTEM" {
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
	// Command-text repository overrides (P1c) leave content-producing forms
	// indeterminate; relative resolution after -C is too easy to misjudge.
	if value, ok := a.env["GIT_DIR"]; ok {
		if !staticGitPath(value) {
			a.reason = roles.Indeterminate
			return
		}
		gitDir, repoUncertain = value, true
	}
	if value, ok := a.env["GIT_WORK_TREE"]; ok {
		if !staticGitPath(value) {
			a.reason = roles.Indeterminate
			return
		}
		workTree, repoUncertain = value, true
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
			a.gitConfig(key+"="+val, depth, cwd)
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
				a.gitRoots = append(a.gitRoots, filepath.Clean(paths.Resolve(value, cwd, "", a.home)))
			case "--work-tree":
				if !staticGitPath(value) {
					a.reason = roles.Indeterminate
					return
				}
				workTree = value
				a.gitRoots = append(a.gitRoots, filepath.Join(filepath.Clean(paths.Resolve(value, cwd, "", a.home)), ".git"))
			case "-c":
				a.gitConfig(value, depth, cwd)
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
				a.gitConfig(configKey+"="+val, depth, cwd)
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
	// Custom aliases and unknown commands cannot be certified without executing Git.
	if !gitBuiltin(args[0]) {
		a.reason = roles.Indeterminate
		return
	}
	sub, operands := args[0], args[1:]
	for i, operand := range operands {
		if operand == "--separate-git-dir" && i+1 < len(operands) || strings.HasPrefix(operand, "--separate-git-dir=") {
			value := strings.TrimPrefix(operand, "--separate-git-dir=")
			if operand == "--separate-git-dir" {
				value = operands[i+1]
			}
			if !staticGitPath(value) {
				a.reason = roles.Indeterminate
				return
			}
			if sub == "init" {
				a.reason = roles.Indeterminate
				return
			}
			a.gitRoots = append(a.gitRoots, filepath.Clean(paths.Resolve(value, cwd, "", a.home)))
		}
	}
	if sub == "init" || sub == "clone" {
		if _, present := a.env["GIT_TEMPLATE_DIR"]; present {
			a.reason = roles.Indeterminate
			return
		}
		for _, arg := range operands {
			key, _, _ := strings.Cut(arg, "=")
			if strings.HasPrefix(key, "--tem") && strings.HasPrefix("--template", key) || strings.HasPrefix(arg, "--template") {
				a.reason = roles.Indeterminate
				return
			}
		}
	}
	// A newly created repository is a protected target even before HEAD exists.
	if sub == "init" || sub == "clone" {
		if gitDir != "" && sub == "init" {
			a.gitRoots = append(a.gitRoots, a.gitPath(gitDir, cwd))
		}
		var target string
		for i := 0; i < len(operands); i++ {
			word := operands[i]
			if word == "--separate-git-dir" {
				i++
				continue
			}
			if word == "-c" && i+1 < len(operands) && sub == "clone" {
				i++
				continue
			}
			if strings.HasPrefix(word, "-") {
				continue
			}
			if sub == "clone" && target == "" {
				target = word
				continue
			}
			target = word
		}
		if target != "" && staticGitPath(target) && (sub == "init" || sub == "clone") {
			root := a.gitPath(target, cwd)
			if sub == "init" && !bareGlobal && !optionIn("--bare --mirror", strings.Join(operands, " ")) && !strings.Contains(strings.Join(operands, " "), "--bare") {
				root = filepath.Join(root, ".git")
			}
			if sub == "clone" && !strings.Contains(strings.Join(operands, " "), "--bare") && !strings.Contains(strings.Join(operands, " "), "--mirror") {
				root = filepath.Join(root, ".git")
			}
			a.gitRoots = append(a.gitRoots, root)
		}
	}
	applyReadOnly := sub == "apply" && gitApplyReadOnly(operands)
	if sub == "apply" {
		if !applyReadOnly {
			a.reason = roles.Indeterminate
			return
		}
	}
	for _, arg := range operands {
		if strings.HasPrefix(arg, "--submodule=diff") || strings.HasPrefix(arg, "--submodule=log") || arg == "--recurse-submodules" && sub != "clone" || sub == "grep" && arg == "--recurse-submodules" {
			repoUncertain = true
		}
	}
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
	if sub == "filter-branch" || sub == "bisect" && len(operands) > 0 && operands[0] == "run" || sub == "submodule" && optionIn(strings.Join(operands, " "), "foreach") {
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
	if repoUncertain || bareGlobal || gitModulesPresent(cwd) {
		a.reason = roles.Indeterminate
		return
	}
	for _, arg := range operands {
		if sub == "grep" || sub == "log" {
			if arg == "process.env" || arg == "import.meta.env" || strings.HasPrefix(arg, "-S") || strings.HasPrefix(arg, "-G") || strings.HasPrefix(arg, "--grep=") {
				continue
			}
		}
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
	// Summary and check modes inspect the supplied patch, not indexed files.
	if !applyReadOnly && indexProtected(resolveGitDirectory(cwd, gitDir), a.home) {
		a.reason = roles.FileInput
	}
}

func staticGitPath(value string) bool {
	return value != "" && !strings.ContainsAny(value, "$`*?[]~\x00\r\n")
}

// gitContentBuiltins are built-in commands outside the safe table; aliases cannot shadow them either.
var gitContentBuiltins = map[string]bool{
	"show": true, "cat-file": true, "grep": true, "archive": true, "format-patch": true, "reflog": true,
	"diff-tree": true, "diff-index": true, "diff-files": true, "range-diff": true, "fast-export": true,
	"config": true, "credential": true, "bisect": true, "submodule": true, "am": true, "apply": true,
	"bundle": true, "difftool": true, "mergetool": true, "filter-branch": true, "notes": true,
	"ls-remote": true, "help": true, "version": true, "whatchanged": true, "annotate": true,
}

func gitBuiltin(name string) bool {
	_, safe := gitSafeOptions[name]
	return safe || gitContentBuiltins[name]
}

type gitOptions struct{ flags, values, optional string }

// Every accepted option has an explicit arity. Unknown options classify the
// whole form as content-producing, rather than silently skipping a value.
var gitSafeOptions = map[string]gitOptions{
	"status":       {"-s --short -b --branch --porcelain --long --show-stash --ahead-behind --no-ahead-behind -z --ignored", "--untracked-files --ignore-submodules --column", "--porcelain --ignored --untracked-files"},
	"log":          {"--oneline --graph --all-match -i --stat --shortstat --numstat --name-only --name-status --all --reverse --first-parent --merges --no-merges --follow --no-color", "-n -S -G --max-count --skip --since --until --after --before --author --committer --grep --format --pretty --date", "--decorate --abbrev --abbrev-commit --no-abbrev-commit --branches --tags --remotes --color --stat"},
	"shortlog":     {"--oneline --all --reverse --no-merges -s -n -e", "--format --pretty --author --committer --grep --since --until --max-count", "--branches --tags --remotes"},
	"diff":         {"--stat --name-only --name-status --numstat --shortstat --quiet --exit-code --cached --staged --no-color", "", "--stat"},
	"branch":       {"--list -l -a --all -r --remotes --show-current", "--sort --format --contains --no-contains --merged --no-merged", "--color"},
	"tag":          {"--list -l -n -a --annotate", "--sort --format --contains --no-contains --merged --no-merged -F --file -m --message", "--color"},
	"remote":       {"-v --verbose", "", ""},
	"rev-parse":    {"--verify --quiet -q --show-toplevel --show-prefix --show-cdup --git-dir --absolute-git-dir --is-inside-work-tree --is-bare-repository --short --symbolic --symbolic-full-name --abbrev-ref --all", "", "--short --abbrev-ref"},
	"rev-list":     {"--all --count --first-parent --merges --no-merges --reverse --left-right --boundary --no-walk", "-n --max-count --since --until", ""},
	"ls-files":     {"-z -c --cached -d --deleted -m --modified -o --others -i --ignored -s --stage -u --unmerged -k --killed --exclude-standard --full-name --error-unmatch --deduplicate", "-x -X --exclude --exclude-from --exclude-per-directory --format", ""},
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
	"clean":        {"-n --dry-run", "", ""},
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
		if len(args) == 1 && optionIn("user.name user.email", strings.ToLower(args[0])) || len(args) == 2 && optionIn("--get --get-all", args[0]) && (args[1] == "x" || optionIn("user.name user.email core.repositoryformatversion core.filemode core.bare core.logallrefupdates core.ignorecase core.precomposeunicode core.autocrlf core.eol core.symlinks core.abbrev color.ui init.defaultbranch pull.rebase push.default fetch.prune", strings.ToLower(args[1]))) {
			return true
		}
		a.reason = roles.Indeterminate
		return false
	}
	table, ok := gitSafeOptions[sub]
	if !ok {
		return false
	}
	if sub == "clone" {
		for i := 0; i < len(args); i++ {
			if args[i] == "-c" && i+1 < len(args) {
				a.gitConfig(args[i+1], 0, cwd)
				if a.reason != "" {
					return false
				}
				args = append(args[:i], args[i+2:]...)
				i--
			}
		}
	}
	if sub == "remote" {
		for _, arg := range args {
			if arg != "-v" && arg != "--verbose" && arg != "show" {
				return false
			}
		}
	}
	if sub == "clean" {
		if len(args) == 0 || !optionIn("-n --dry-run -f -fd -fdx", args[0]) {
			return false
		}
		for _, target := range args[1:] {
			if strings.HasPrefix(target, "-") || a.inputProtected(target, cwd) {
				return false
			}
		}
		return true
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
			if optionIn("add commit restore checkout switch blame rm mv", sub) && !(sub == "rm" && slices.Contains(args, "--cached")) && a.inputProtected(arg, cwd) {
				a.reason = roles.FileInput
				return false
			}
			continue
		}
		key, value, attached := strings.Cut(arg, "=")
		if sub == "log" && len(arg) > 1 && strings.Trim(arg[1:], "0123456789") == "" {
			continue
		}
		if sub == "commit" && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.Contains(arg, "m") && strings.Trim(arg[1:strings.IndexByte(arg, 'm')], "as") == "" {
			value := arg[strings.IndexByte(arg, 'm')+1:]
			if value == "" {
				i++
				if i >= len(args) {
					return false
				}
			}
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
			if optionIn("-F --file --exclude-from", key) && value != "-" && a.inputProtected(value, cwd) {
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

func gitModulesPresent(cwd string) bool {
	for dir, count := cwd, 0; dir != "" && count < 128; dir, count = filepath.Dir(dir), count+1 {
		if _, err := os.Lstat(filepath.Join(dir, ".gitmodules")); err == nil || !os.IsNotExist(err) {
			return true
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return false
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	return false
}

// gitApplyReadOnly requires an explicit check or summary mode and rejects
// every option that might also apply the patch or redirect its targets.
func gitApplyReadOnly(args []string) bool {
	readOnly := false
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		if optionIn("--check --stat --numstat --summary", arg) {
			readOnly = true
			continue
		}
		if optionIn("-v --verbose -z --recount --allow-empty", arg) || strings.HasPrefix(arg, "--exclude=") || strings.HasPrefix(arg, "--include=") {
			continue
		}
		if arg == "-p" || arg == "-C" {
			i++
			if i == len(args) {
				return false
			}
			if _, err := strconv.Atoi(args[i]); err != nil {
				return false
			}
			continue
		}
		if len(arg) > 2 && (strings.HasPrefix(arg, "-p") || strings.HasPrefix(arg, "-C")) {
			if _, err := strconv.Atoi(arg[2:]); err == nil {
				continue
			}
		}
		return false
	}
	return readOnly
}
