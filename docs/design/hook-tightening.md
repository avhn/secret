# Hook tightening decisions for M2

## Scope and limits

The default Go build analyzes Bash tool calls through a bounded AST policy. The
installed hook remains `hooks/guard-secrets`; no plugin manifest or `hooks.json`
has changed. Synthetic tests do not establish installed-hook containment, host
shell-dialect coverage, or failure-blocking behavior.

The security model is accident prevention, not a sandbox. The analyzer does not
execute Git, a shell interpreter, child commands, or provider value APIs while
making a decision. It reads only the bounded metadata described below. Real-host
failure tests, dialect evidence, and supported-platform CI remain separate gates.

## Current policy

- P0 recovers panics from decoding or analysis and emits a fixed denial without
  the panic payload. Output errors still propagate, so an unwritable host channel
  is not a failure-blocking guarantee.
- P1 denies Git subcommands outside the case-sensitive built-in table, including
  custom aliases and inline `-c alias.*`, without reading Git configuration for
  aliases. Users can run an alias's expanded built-in command instead. It applies
  exact global-option arities, inert-key allowlisting, index gates, and
  command-running surface checks. Unknown options, subcommands, and ambiguous
  repository locations deny.
- P1 content checks use a bounded resolved index, rather than the work tree.
  Protected index entries, protected path arguments, and indeterminate
  repositories deny. Ignored and untracked `.env` files do not block `git log
-p`; deleted-only history remains an exclusion. Index parsing supports versions
  2, 3, and 4 under byte, entry, path-length, and checksum limits. Unsupported,
  inaccessible, malformed, split, sparse, SHA-256, or otherwise indeterminate
  index states deny.
- P2 analyzes `find` children after wrapper handling. Only listed metadata
  children are exempt from bounded scope inspection; unknown children, including
  `echo`, are readers. Symlinks, uncertified operand streams, and unsupported
  `parallel` grammar deny. A supplied non-protected `xargs` argument-list file is
  a modeled operand source, while stdin-fed readers inspect the cwd scope.
- P3 uses archive option and mode tables. Creation inspects bounded input scopes,
  including symlinks. Stdout and extraction-to-command forms always deny.
  Listing is metadata-only, including protected-looking member names. `cpio` and
  `7z` model listing only; other forms deny. Literal safe compressor and
  checkpoint commands are analyzed as shell text.
- P4 and P5 invalidate later relative reads after ambiguous directory changes,
  special tilde directories, `CDPATH`, relevant `shopt` settings, dynamic
  `/proc` paths, and descriptor-directory aliases. Only specified harmless proc
  files are exempt.
- P6 models jq program-file selection, sed file and execution forms, and awk
  literal file or system operands. Sed script files are inspected only through a
  non-protected alias as bounded regular files of at most 8 KiB. Missing,
  non-regular, unreadable, oversized, computed, or otherwise indeterminate
  scripts deny. Sed script-file lookup uses native absolute paths on Windows,
  preserving the regular-file and symlink checks.
- P9 analyzes `-c` text for additional shell dialects and BusyBox or ToyBox shell
  applets. P10 validates complete sed scripts before classifying file and
  execution surfaces. P11 normalizes Bash option words before invalidating
  uncertain path semantics. P12 tracks indirect assignment to environment names
  consulted by later Git, shell, or ripgrep commands.
- P13 expands single-element glob braces under explicit nesting and alternative
  limits. P14 treats `apply_patch` heredocs as patches, rather than inert prose;
  protected or malformed patches deny and safe framed patches remain allowed.
- Inline Git configuration outside the inert `gitConfigInert` key allowlist
  always denies, including `-c`, `--config-env`, `GIT_CONFIG_COUNT`, and
  `GIT_CONFIG_PARAMETERS`. Inline editor and pager assignments accept only named
  editor or pager programs and literal arguments; inline SSH, askpass, proxy,
  and external-diff assignments deny. Inherited editor and pager settings are
  not analyzed.
- Shell hook code in `BASH_ENV` and `ENV` is treated as a file input. An
  inline `BASH_ENV` pointing to an unprotected script also denies because its
  sourced code is not certified. Inline `BASHOPTS` and `SHELLOPTS` with
  path-changing options invalidate child shell directories. Other hook variables remain bounded shell fragments. Interpreter
  environment access is denied for recognized environment reads in interpreter
  arguments. No interpreter runs during analysis.
- Sed uses a safe-subset allowlist: simple addresses, inert commands, bounded
  labels, final one-line text commands, and final-line literal read/write
  filenames. Execution commands and substitution execution/write flags always
  deny. A positional script before `-e` or `-f`, or an inline assignment to
  `POSIXLY_CORRECT`, denies. Multiple explicit scripts join with newlines.
- Shell invocations without `-c` or a script file deny, including here-doc and
  here-string input. Script-file operands and shell startup files must be
  non-protected regular files. The scanner peels `setsid` and `script -qc`,
  consumes shell option values, and rejects descriptor-based `source`. Inline `LESS*` settings
  other than inert `LESS`, and append assignments to sensitive names, deny.
- Git helper names classify only when dispatched by bare name or from a
  `git-core` directory; protected operands deny even for those helpers. Git
  content commands deny for `.gitmodules` or submodule expansion. Command names
  classify case-insensitively. Writes to Git configuration, `.gitmodules`,
  worktree gitdirs, and global configuration deny, including redirected output,
  command destinations, and in-place edits.

The policy intentionally excludes simulated copy, link, and extraction state;
computed script literals and `eval`; object-content reads; and claims about host
installation or containment. Seven Bash-only external dependency fault cases are
covered by Go scanner fault-injection tests, not command-text variants.

## Current reviewed divergences

Every row in `testdata/inventory/go-hook-divergence.tsv` has a named entry below.
`deliberate-find-shim` is an injected dependency failure that Go does not execute,
not a permission bypass. `deliberate-tightening` is an owner-approved
indeterminate-input or audited input/output policy tightening.

| Cases                                                                                                                                                                              | Category              | Reason                                                                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `audit-arithmetic-unknown`                                                                                                                                                         | deliberate-tightening | `(( $(cat file) ))` contains a content-producing substitution and cannot be certified from arithmetic syntax.                                                                                |
| `audit-cases5-6`                                                                                                                                                                   | deliberate-tightening | Ripgrep names mode with `--pre cat` invokes a content-producing child and cannot use the names-only shortcut.                                                                                |
| `audit-cases6-7`                                                                                                                                                                   | deliberate-tightening | Clustered xargs `-0a` consumes a protected argument-list file before invoking its child.                                                                                                     |
| `audit-cases7-2`                                                                                                                                                                   | deliberate-tightening | A symlinked ancestor can reach an actual credential file before `..`; a final-symlink alias exception cannot certify that input.                                                             |
| `malformed_safe`, `oversized_safe`                                                                                                                                                 | deliberate-tightening | An absent framing pair, ambiguous header, or patch above the 40 KiB limit cannot certify safe target paths. Recognized protected headers deny even without framing.                          |
| `active_safe_command`                                                                                                                                                              | deliberate-tightening | `$c package.json` does not establish the executable or its input and output roles.                                                                                                           |
| `deep_safe`                                                                                                                                                                        | deliberate-tightening | Six nested `shell -c` layers exceed the Go analysis depth and deny.                                                                                                                          |
| `audit6_sed_comment`, `audit6_sed_text_line`, `audit6_sed_insert_line`, `audit6_sed_change_line`                                                                                   | deliberate-tightening | GNU sed reads these as a comment or as a/i/c text, so Bash allows them; Go denies any script whose later commands follow a comment or text command on one line.                              |
| `policy_v2_sed_script_clean`                                                                                                                                                       | deliberate-tightening | A `-f` script file holding `code` is a final one-line `c` command to GNU sed; Go certifies only scripts whose file text matches the safe subset exactly, so it denies.                       |
| `grep_find_exit`, `grep_find_exit_count`, `grep_timeout`, `grep_timeout_count`, `rg_find_exit`, `rg_timeout`                                                                       | deliberate-find-shim  | Bash denies when the injected `find` exits or times out. Go does not execute `find`; its walk errors, permissions, loops, budgets, and deadlines deny under dedicated fault-injection tests. |
| `unresolved_file_safe`, `unresolved_listing_safe`, `unresolved_literal_safe`, `unresolved_no_eval`, `unresolved_positional_safe`, `unresolved_redirect_safe`, `unresolved_wc_safe` | deliberate-tightening | Unknown parameter or substitution output cannot certify a non-protected content-producing input. The analyzer never executes a substitution to decide.                                       |

## Permanent synthetic evidence

Audit fixtures are synthetic and permanent in `testdata/hook/audit-cases.json`
and `internal/hook/policy/testdata/audit3.json`. They cover JSON adapters,
Git, archive, directory, find, xargs, parallel, jq, script, and patch decisions.
Fixtures contain fabricated files, symlinks, and generated indexes only. The
variant corpus preserves literal quoting, escaping, brace, and wrapper forms;
active expansions are not made inert, heredoc delimiters are not changed to
disable substitution, and invalid arithmetic rewrites are excluded.

## Measurement and regeneration

The default path uses bounded AST analysis with 64 KiB envelopes and 40 KiB
recursive fragments. Word, brace, recursion, glob, and scan limits remain
bounded. The timing wrapper measures process launch plus decision, not an
installed host callback.

Regenerate with `python3 -I tests/gen-go-hook-divergence.py ABSOLUTE_BINARY`.
It runs the shell suites and both implementations on audit fixtures, refuses
unreviewed suite categories or missing tightening-table entries, and writes the
inventory mechanically. Run `bash tests/go-hook.sh guard ABSOLUTE_BINARY claude`
and the corresponding Codex command for exact inventory checks.

`tests/trial-go-hook.py` builds a disposable default binary and prints grouped
counts and p99. Regenerate denied-command metadata fixtures with
`python3 -I tests/gen-hook-variants.py`; it keeps Bash-only injected dependency
faults out of command-text variants and tests their Go scanner boundary through
fault injection.
