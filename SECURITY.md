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
print-access-token`, AWS credential and ECR/STS/SSO token output, Azure access
  tokens, Heroku/Vault/doctl/glab tokens, `kubectl create token`, `direnv export`,
  `op read`, `pass`, `secret-tool`, `security -w`, clipboard readers), and
  content searches over trees that hold protected files, including `ack` and
  `ack-grep`, which cannot rely on ripgrep exclusions or Git ignore rules. The
  shipped guard also rejects control characters in shell commands, gates
  content-producing Git commands on bounded tracked index names
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
  roots. The Go hook also treats inherited GIT_DIR and GIT_COMMON_DIR values as
  protected write roots, including lexical and physical aliases without HEAD
  metadata; this is not a claim of equivalent installed Bash coverage.
  Non-reader argument words containing Git configuration tokens deny,
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
  protected files. A printer piped straight into `secret stash FILE KEY`,
  `docker login --password-stdin` or `helm registry login --password-stdin` is
  allowed, since the value goes directly to a store or login consumer instead
  of output. AWS, gcloud, Azure, Heroku, Vault, doctl, glab and direnv printer
  subcommands are recognized in order despite global, interleaved or unknown
  options; an unknown option's argument cannot hide these printers. Printer
  options share a normalizer that removes known value operands and recognizes
  attached values and short-option clusters, including Keychain stdout/stderr
  flags and clipboard output flags. Boolean printer flags accept case-insensitive
  true/false, yes/no, on/off and 1/0 values; false flags alone do not request
  token output. Raw kubectl config views, secret content output formats, op OTP
  retrieval and raw op signin output use the same normalized option roles.
  Resolved keyring and secret-tool actions
  bound their data operands, so service names and attribute values are not
  mistaken for later retrieval verbs. Known launcher children re-enter the full
  command policy, preserving masked metadata and env-file consumer roles rather
  than relying on a partial list of reader names. Recognized children behind
  otherwise unknown launchers receive the same reader and printer checks; the
  unknown launcher's own protected-argument backstop remains conservative. Directory options on env,
  sudo, package runners, make and Docker Compose anchor reader operands at the
  child's cwd, including incoming cwd alternatives and make short-option
  clusters, without moving later shell siblings. Parallel templates are shell
  source regardless of whitespace in the first word; source-list operands retain
  protected-path checks. Attached Parallel job counts and taskset boolean
  clusters, hexadecimal masks and CPU lists retain full child classification.
  Non-consumer Docker actions do not fail consumer-child parsing. Lua `os.getenv`
  (including versioned Lua and LuaJIT executables) and Rscript `Sys.getenv` code
  is treated as environment access for inline code and stdin. Legacy tar option
  bundles are normalized before stdout extraction
  checks. This includes ECR/ECR Public passwords and authorization tokens,
  STS session, assumed-role and federation credentials. An intermediate command
  such as `cat` is not that transport; only the single direct pipe is allowed.
  Literal reader aliases are inspected at their use sites. Alias definitions
  with directory-changing or unresolved effects retain an uncertain cwd for
  later readers. Subshells, command substitutions, non-final pipeline segments
  and uncalled function bodies do not publish their aliases to the caller.
  Bounded literal `eval` source can preserve the caller cwd when
  its directory changes stay inside subshells or command substitutions; protected
  reads inside those scopes still deny. Fully literal interpreter argv launches
  and literal command strings re-enter reader and credential-printer analysis,
  including global printer options and parenthesis-free Ruby/Perl argument
  lists. Launch extraction skips interpreter comments and quoted call text.
  Curl file URLs (including case-insensitive `file:/path` and percent-encoded
  paths), upload/config/JSON/write-out/header input files, multipart file lists
  and header files, and gh API input files use protected path checks. Curl
  literal option values, `--data-raw`, `--form-string` and `name=content` URL-encoded
  payloads remain data, not implicit file reads.
- **Bounded audit-27 source and input checks.** Interpreter executable source and
  stdin reject unterminated recognized literals; ordinary script arguments remain
  data with protected-path witnesses. Required interpreter operands must exist,
  while documented optional operands and explicitly empty source stay supported.
  Go anchors modeled PHP, Node and Bun literal launch readers at their child
  directories. It maps Docker directory binds back to host reader paths and
  handles UV and systemd-run child directories; this does not model arbitrary
  container code. These Go models do not establish equivalent Bash coverage.
  File-backed xargs names remain uncertified through wrappers and compound
  redirects, but a pipe replacing stdin replaces inherited filename provenance.
  Unquoted static scalar expansions undergo bounded field splitting; a known
  empty IFS disables splitting, and uncertain mutations cannot certify it.
  Literal recursive eval may preserve shell state only after bounded syntax and
  child analysis; dynamic source, protected reads and excessive recursion deny.
  No candidate source is executed to establish these decisions.
  Bash preprocessing uses linear CRLF normalization and alarm-bounded helpers.
  Decoded argv is capped at 256 arguments and 8 KiB including separators, with
  the existing multiline explicit-shell allowance; Go applies the same argv
  preparation caps. File-tool paths are bounded before expensive matching.
  Decoded tool-name controls deny before unsupported-tool dispatch. Patches
  require complete bounded framing, typed workdirs and ordered path sections;
  an End of File marker is valid only at the end of an update hunk. The previous
  Bash malformed-patch exception is closed. Both Go adapters validate apply_patch.
- **Bounded audit-28 launch, search and patch checks.** Go retains literal Deno
  executable/argv witnesses across unrelated option properties, recognizes PHP
  literal `array(...)` argv with consecutive numeric keys, and preserves trailing
  operands of attached env split-string options. systemd-run configured credential
  assignments apply to its child only. Invalid timeout/taskset launches and
  unsupported setsid options deny. Hidden substitutions in double-quoted
  parameter words are inspected, and quoted arithmetic operands, misplaced
  reserved words and commandless coprocess redirects deny conservatively.
  Go retains stricter arithmetic/function/time controls listed in
  `docs/design/hook-tightening.md`; these are not claims of full shell semantics.
  Shell-fed apply_patch bodies use bounded framing and protected-target checks
  after wrapper dispatch. Go uses the child cwd and effective redirect scope,
  so a child stdin redirect shadows an ancestor patch body without masking
  existing same-command denials. Grep is classified on either host; only an
  absent output mode defaults to names-only, while empty or unknown strings
  receive content checks. Go checks whitespace/comma selector alternatives as
  well as the original selector, retaining conservative order-sensitive denials.
  Configured credential paths compare case-insensitively on every OS. Grep
  glob/type values are capped at 4,096 bytes and 128 slash separators, including
  names-only calls. Invalid or over-budget brace selectors deny, and root-glob
  recursion requires progress. Bash bounds first-line extraction before copying
  oversized source, cumulative credential-selector suffix work, and brace scan
  steps and nesting (64 levels). Go also bounds unquoted shell brace depth at
  64; quoted data remains inert. Bash arithmetic commands and C-style loop
  clauses receive non-evaluating operand validation after bounded quote removal
  and continuation normalization, with original substitutions still inspected.
  Existing phase, analysis and overall deadlines remain unchanged. Evidence is
  synthetic guard input only, not installed-host timeout or containment evidence.
- **Nonempty malformed envelopes deny explicitly.** Only zero-byte input has no
  tool call. Whitespace-only input, raw NUL, invalid UTF-8, duplicate JSON object
  keys, missing or mistyped shell commands and workdirs, missing tool names,
  whitespace-only tool names, mistyped file-tool paths and mistyped Grep
  patterns/globs/types/paths/output modes deny before command analysis.
  NotebookEdit requires `notebook_path` as its authoritative target; an extra
  `file_path` cannot replace or override it. The Bash guard caps raw envelopes at
  1 MiB plus 64 KiB, matching Go, before Unicode or JSON parsing. Its bounded
  Perl validator rejects non-JSON number syntax and unmatched escaped surrogates
  throughout keys and values, retaining raw NUL, UTF-8 and duplicate-key checks.
  Both validators permit at most 4,096 object keys, 32,768 JSON tokens (including
  punctuation), and 128 container levels. Both guards bound unnormalized envelope
  paths to 4,096 slash separators before redundant components are removed.
  Without Perl, only bounded 8 KiB,
  unescaped ASCII JSON retains the dependency-light names-only path, with strict
  number syntax checked before jq, independently of scalar delimiters and JSON
  whitespace. Workdir controls deny before extraction.
  Envelope preparation and analysis each have a two-second budget (with one
  phase tick of rounding tolerance for Bash 3.2's integer clock), and a
  four-second overall decision deadline starting before reads and preprocessing.
  Bash 3.2 reserves the final overall clock tick for emitting a denial, rather
  than continuing analysis up to the coarse-clock deadline. Statement-fanout and
  tokenizer control checks scan bounded chunks, avoiding slow whole-body pattern
  replacements before the next deadline check. Substitution collection and its
  nested parser check the shared budget after bounded scanner steps, including
  escaped bytes, so inline and here-string preprocessing cannot defer exhaustion
  until interpreter analysis. Text without expansion markers skips collection.
  Bounded reads time out and every otherwise-allowing exit checks both its phase
  budget and that overall deadline. Shared path normalization checks the budget
  while removing and rebuilding components, including envelope cwd components;
  normalization failure cannot certify a safe file target. Physical ancestor
  resolution checks that deadline before and after its alarm-bounded Perl
  subprocess, which also caps path separators before filesystem work.
  Raw protected-name scanning has its own 200 ms subprocess alarm and checks
  the shared budget before and after scanning. Filename word runs match only
  from their start without backtracking, rather than retrying every suffix of
  long public literals in dotted interpreter calls. Incomplete raw scans deny,
  including oversized heredocs; inert quoted writer data retains its role.
  Interpreter Git-path and credential-literal scans use alarm-bounded extraction
  rather than whole-body Bash regex matching, check the shared budget while
  consuming literals, and deny incomplete extraction, including oversized
  heredocs. Confirmed shell source has its framing checked with an alarm-bounded
  Bash noexec parser, with startup files disabled, before command analysis or
  oversized-heredoc early exits. Missing operator operands and unbalanced
  compound commands deny as indeterminate syntax. Heuristic argument and
  interpreter-literal scans retain positive reader and printer witnesses even
  before malformed trailing text, without requiring inert prose to be valid
  shell syntax. Explicit shell children still receive strict framing checks,
  including within those heuristic scans. Candidate commands are never executed
  by this check.
  Failed reader or configured-path
  normalization denies without treating an empty result as a safe filename.
  Synthetic deadline tests do not establish installed-host timeout behavior.
  Existing command and heredoc budgets still apply. The Go interpreter scanner
  caps raw literal extraction before filesystem metadata work and checks bounded
  raw-body regex windows against its shared two-second analysis deadline. Source
  limits count decoded literals, not shell quote-escape fragments. The envelope
  read has a separate two-second timeout, so these are not a strict two-second
  end-to-end wall-time guarantee. Synthetic large-body and delayed-input checks
  do not establish installed-host fail-closed behavior.
- **Audit-29 Go syntax witnesses** include static computed Deno argv keys,
  constructor-local child cwd, package executable paths containing `@`, expanded
  patch headers, substitutions hidden in extglobs and stored arithmetic values
  across loops and assignment merges. Unsupported deep backquote residue and
  active arithmetic reevaluation deny conservatively. Intermediate glob
  directories may include hidden stores even without explicit dotglob options;
  this intentionally over-denies some default-shell patterns. These scanners
  inspect synthetic syntax and path metadata, never execute candidate commands.
  Bash now permits certified public Parallel null/fd pipelines and literal
  read-only metadata children; protected scopes, aliases and compound reader
  templates still deny. Exact remaining harmless Bash over-denials are listed in
  docs/design/hook-tightening.md, not generalized allow exceptions.
- **Credential filename coverage** also includes `.aws/config` as well as
  `.aws/credentials`, `.kube/config`, paths named by a literal `KUBECONFIG` path
  list, `AWS_CONFIG_FILE` or `AWS_SHARED_CREDENTIALS_FILE` (including alternatives
  assigned along conditional branches in the same shell request). Only
  `KUBECONFIG` is a colon-separated path list; each AWS variable names one file,
  including literal colons in filenames. Coverage also includes
  `application_default_credentials.json`,
  `.config/gcloud/credentials.db`, `.config/gcloud/access_tokens.db`, files under
  `.config/gcloud/legacy_credentials/`, `.vault-token`,
  `.terraform.d/credentials.tfrc.json`, `.cargo/credentials.toml`,
  `.cargo/credentials`, `.pgpass`, and the user's `~/.yarnrc.yml`. These are
  filename and metadata checks, never inspections of credential contents.
  Relative configured paths are resolved at the reader's effective cwd,
  including wrapper and workspace alternatives. Both lexical names and physical
  aliases of these paths and the home Yarn file are protected; missing targets
  retain their lexical protection. Missing suffixes on configured and reader
  paths resolve through their deepest existing ancestor, so an aliased parent
  such as macOS `/var` does not lose the physical witness. Unresolved reader
  operands naming these credential-path variables also deny. Interpreter inline code, stdin and
  eligible oversized heredocs check quoted filename literals with the same
  credential classifier, including bare names relative to the effective cwd.
  The example ripgrep config excludes the fixed names; arbitrary configured
  paths require scope checks rather than certification from that config alone.
- **Templates outside stores stay readable.** `.env.example`, `.env.sample`,
  `.env.template` and names ending in `.env.example`, `.env.sample` or
  `.env.template` are exempt outside `.secrets/` and other protected credential
  contexts. The same rule applies to explicit Git blob paths, including diff
  operands naming earlier revisions: a clean current index does not exempt a
  protected historical path. A Git grep pattern such as `git grep -- '*.env*'`
  is search text, not a protected file operand; its content scope still needs
  the ordinary Git index checks.

## What it does not protect

These are outside the threat model. Reports about them are welcome as
documentation or hardening suggestions, but they are not vulnerabilities:

- **Known audit-29 follow-ups.** M2.1 retains malformed coprocess framing,
  raw path/component byte-limit parity, native patch control bytes and incomplete
  patch-body grammar (U2, U15, U16, U17). Go now rejects the reported opaque
  extglob and deep-backquote malformed forms, while some malformed nested
  backquotes still allow in Bash (U8/U11). Opaque pipeline patch stdin is denied
  by Go after the a3b0306 review; retained Bash provenance limits remain U3 work.
  These limits are not evidence that arbitrary malformed input is rejected.
  Audit 27 to 29 shared/Bash-only class (i) findings remain coverage backlog;
  closing Go directional differences does not establish installed Bash coverage.
- **Known audit-28 coverage limits.** The retained Bash guard does not cover all
  explicit-shell positional argv forms, awk pipe/getline readers, whitespace-list
  Grep selectors, attached systemd-run configured credential assignments or
  recursive grep through protected symlinks. Shared gaps include UV tool-runner
  directory options and relocated gh hosts.yml selected by XDG_CONFIG_HOME or
  GH_CONFIG_DIR. These remain coverage backlog items, not evidence of protection;
  Go-specific closures do not imply equivalent installed Bash coverage.
- **Project Yarn configuration.** A project `.yarnrc.yml` remains readable,
  even though an `npmAuthToken` entry can contain a secret. Only the user's
  `~/.yarnrc.yml` is protected by this filename rule. Keep project tokens out
  of that file and use secret transport for token-bearing configuration. The
  example ripgrep config conservatively excludes all `.yarnrc.yml` files.
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
  denies instead of allowing the tool call. A raw substring scan cannot certify
  an allow after static analysis fails, even when the incomplete input contains
  no obvious secret name. This includes unclosed shell quotes, missing launcher
  option values, unsupported ANSI-C NUL/internal marker bytes and exhausted
  brace-expansion limits. Supported literal ANSI-C escapes remain analyzable.
  This is a hook decision, not a sandbox guarantee: a disabled or missing host
  hook cannot enforce it.
  The interim Bash guard also denies requests it cannot analyse within its
  two-second budget, including very long `&&` chains. Split the command into
  shorter calls. Kubectl secret content formats, including inline
  `custom-columns=...`, are credential output; pod output and secret names stay
  metadata. Curl uploads of unresolved shell variables may still transmit
  sensitive values; avoid them with credentials.
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
