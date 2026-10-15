# Security model

`secret` is accident prevention for coding agents. It keeps credential values
out of an agent's context when the agent reaches for them by habit or mistake:
`cat .env`, `printenv`, `gh auth token`, a content search over a directory
holding a store. It is **not a sandbox** and does not contain an agent that is
deliberately trying to read a secret.

## What it protects

- **Store values never pass through the CLI's own argv or diagnostics.** `show`
  and `list` print names, masked lengths and paths only. `run` delivers
  selected keys through the child's environment and replaces every loaded value
  with `<redacted>` on the child's stdout and stderr. If a redaction filter
  fails, `run` stops the child and exits 1 rather than printing unfiltered
  output.
- **Writes are private and atomic.** `stash` reads values from a hidden prompt
  or stdin, writes the replacement inside a private 0700 directory, and renames
  it onto the store under a lock. It refuses symlinked and non-regular targets.
- **The guard denies the common accidents** before a tool call runs: reading
  store files and well-known credential files (cloud CLI credentials, Docker
  and gh config, npmrc, pypirc, SSH private keys, `/proc/*/environ`), dumping
  the environment, credential printers (`gh auth token`, `gcloud auth
print-access-token`, `aws configure get`, `op read`, `pass`, `secret-tool`,
  `security -w`, clipboard readers), and content searches over trees that hold
  protected files. The shipped guard also rejects control characters in shell
  commands, gates content-producing Git commands on bounded tracked index names
  and protects covered archive reads, including BusyBox tar stdout extraction,
  and detects shell hook variables that can launch readers. Inherited Git editor
  and pager settings are user configuration, not shell text; values assigned in
  the tool command permit only literal allowlisted editor/pager programs with
  non-protected arguments; Git diff, SSH, proxy and askpass overrides deny.
  Inline Git configuration accepts only inert keys, and sed scripts use a
  conservative safe-command allowlist. Ordinary writes to `.git`, `.gitmodules`
  and user Git configuration deny to prevent planted repository commands.
  The Bash hook also checks nested commands under unmodelled wrappers and
  coprocesses, refuses unverified shell stdin, and resolves write targets
  through ancestor worktree gitfiles and home configuration paths. The
  Claude Code matcher includes MultiEdit and NotebookEdit file paths.
  Protected Git write targets include independent directories identified by a
  HEAD file, objects directory and refs directory, and declared Git directory
  roots. Non-reader argument words containing Git configuration tokens deny,
  including attached option values and interpreter code. The shell scanner
  denies over-limit token streams rather than falling back to a raw regex.
  Generic shell-looking arguments are inspected for positive findings; known
  command slots such as flock -c, make --eval and rsync -e are inspected
  strictly. The Bash guard also checks independent bare Git directories as
  destinations, refuses unsafe Git apply options and template directories,
  and limits shell statement fanout. Over-budget commands deny, including
  oversized otherwise safe requests; split them into smaller tool calls.
  Bash permits up to 256 command words (heredoc body text does not count).
  A trailing CR in CRLF input is ignored, but a CR in the middle of a line
  still denies.
  Reader children of xargs given a file, heredoc or here-string also deny
  because their input names cannot be certified. These checks do not execute
  the command.
  This is syntax-only accident prevention, not execution isolation.
  Protected paths are matched after brace and `$IFS` expansion and through
  symlink aliases. The P18 backstop scans shell input bodies, inline code,
  strict command slots and unknown commands. Role-classified operands of
  modelled commands retain their existing rules: `secret show`, `run` and
  `stash` may name stores; metadata commands and env-file consumers may name
  protected files. A printer piped straight into `secret stash FILE KEY` is
  allowed, since the value goes into a store instead of output.

## What it does not protect

These are outside the threat model. Reports about them are welcome as
documentation or hardening suggestions, but they are not vulnerabilities:

- **Transformed output.** Redaction matches literal values. Base64, URL
  encoding, hex, substrings, reversed or split values are not caught.
- **Shell indirection the guard cannot resolve statically.** The guard
  tokenizes commands and never evaluates them. Variables set elsewhere, files
  of commands, `eval`, aliases, functions, interpreters reading paths from
  their input, and other dynamic constructs can name a protected file without
  spelling it. Same-command copy, symlink or archive laundering, including
  `cp -r`, `ln -s` and an archive read following an archive creation, is not
  traced. Archive extraction to disk is allowed and member names inside an
  archive are not inspected, so an archive can still carry `.git` paths; only
  the extraction destination and stdout extraction are checked. Concatenated or computed script literals and `eval` are not reliably
  resolved. The guard does not infer protected inputs from an unresolved
  operand whose command text names no protected file.
- **Deliberate shell and repository construction.** Piped `tee` or `echo`
  text fed to an interpreter, scripts or build files written and run in one
  command, and hand-built Git directories are not tracked across command
  boundaries. Unusual glob classes and rare option abbreviations may also
  evade static classification. These are outside the accidental-read model.
- **Shell scripts read from stdin.** A shell without `-c` or a certifiable script file is denied, including static here-strings and quoted here-docs. Use `sh -c` for literal code.
- **Git probe isolation.** The Bash guard runs index probes with a scrubbed Git environment, disabled fsmonitor, untracked cache and hooks, and a separate session. The guard does not execute repository Git configuration as part of its own index inspection. Git config writes and unmodelled getters are denied; custom editor and pager settings assigned inside command text accept only inert program-specific options.
- **Custom Git aliases are denied.** The hook does not read Git configuration: aliases can execute arbitrary shell commands and configuration resolution can differ from the command environment. Only case-sensitive built-in Git subcommands are classified. Run the expanded built-in command instead of an alias.
- **History no longer tracked.** Git content-producing commands are checked
  against a bounded `git ls-files -z` index name list, not blob contents or a
  worktree scan. An ignored, untracked `.env` does not block ordinary history
  inspection. Paths deleted or renamed away from the current index can still
  appear in old Git objects without being found by the index check. The Bash
  guard's index probe runs under a short timeout with repository config hooks
  disabled; a probe that times out (for example in a very large repository)
  is treated as protected, so content-producing Git commands deny there.
- **Inherited variable values in argv.** Tools such as `basename "$TOKEN"`
  and `ls "$TOKEN"` may print inherited secret values. Apart from existing
  `echo` and `printf` checks, arbitrary argv expansion is not tracked.
- **What env-file consumers do with values.** `docker run --env-file .env`,
  `node --env-file=.env` and `dotenv -e .env -- CMD` are allowed. Obvious
  printing children (`env`, `printenv`, `docker compose config`) are denied,
  but an arbitrary program given those values can still print them.
- **Executable substitution.** The guard trusts command names. A different
  program named `secret`, `cat` or `jq` earlier on PATH is not detected.
- **Tools the guard does not see.** The hook covers Claude Code's Bash, Read,
  Grep, Edit, Write, MultiEdit and NotebookEdit tools, and Codex's Bash shell
  hook and `apply_patch`.
  Hosted tools such as web search, MCP servers, other agents and other editors
  are not covered. Codex `write_stdin` input to an already running exec session
  is not re-checked by this hook. Codex's current `exec_command` hook input
  also omits its per-command `workdir`: if it differs from the hook's `cwd`,
  relative file operands are checked against the wrong directory. The guard
  honors `tool_input.workdir` when a shell adapter supplies it.
- **Process-level visibility.** A child that puts a value in its own argv
  exposes it to the local process list. Descendants a `run` child leaves
  running are not supervised. Any process running as the same user can read
  the stores and, while a child runs, its environment.
- **Visibility limits.** A nonempty malformed request or failed static analysis
  denies instead of allowing the tool call. This is a hook decision, not a
  sandbox guarantee: a disabled or missing host hook cannot enforce it.
  The interim Bash guard also denies requests it cannot analyse within its
  two-second budget, including very long `&&` chains. Split the command into
  shorter calls. `kubectl get secret -o custom-columns=...` can select secret
  data without using a standard printer format, and curl uploads of unresolved
  shell variables may transmit sensitive values; avoid both with credentials.
- **Ignored dependency trees.** A content search over a tree skips `.git` and
  `node_modules` unless `--hidden`, a glob or an explicit path brings them
  into scope, so a protected file inside them is not detected.
- **Clipboard consent.** `secret clip` is allowed for agents because the value
  never reaches their output; the skill limits it to explicit user requests,
  which a hook cannot verify.
- **Searches without the protective ripgrep config.** Plain `rg` is treated as
  safe only when the effective ripgrep config excludes store files (see
  `examples/ripgreprc`) and adds no option that widens what is read;
  otherwise content searches over trees holding protected files are denied.

## Reporting

Use GitHub's private vulnerability reporting on this repository for anything
that lets a value reach agent output through a path the guard or the CLI
claims to cover. Describe the command or tool call and the observed decision.
**Never include a real credential**; synthetic values like `synthetic-token`
reproduce every case the test suites cover.

### Go guard audit 15 scope

The Go guard treats `.envrc` as protected direnv configuration, alongside
`.env` stores. The example ripgrep config excludes it; previously copied
configs need the additional `--iglob=!.envrc` line before they can certify a
protected-name search. Explicit `fd` execution and package-runner command
slots are analyzed as children, not name-only listings. Unquoted heredoc
substitutions are analyzed even when stdout becomes a Git or GitHub message.
Conditional directory changes retain bounded sets of possible working
directories instead of recursively repeating the remaining command text.
Names-only searches and filtered public-source searches can pass without
printing protected contents. Filters do not exempt matching files inside
store directories. These are synthetic policy guarantees, not installed-hook
containment or evidence of macOS and Windows runtime coverage. Windows
invalid-name path errors cannot certify a file read, while permission and I/O
errors remain fail-closed.

For the Go search model, an unmatched credential glob retains its parent
context, including symlink resolution. Repeated `fd --extension` filters are
alternatives, not a way to replace an earlier sensitive extension. Ripgrep's
JSON output remains a content mode even when combined with a count option;
the names/count exemption is not a general exemption for content printers.
