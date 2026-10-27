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

## M5e PowerShell and unknown Windows shell contracts

Named tightening: `m5e-powershell-contract-denial` (deliberate-tightening).
The Go hook now recognizes the exact `PowerShell` tool name instead of returning
no decision. Claude PowerShell, Codex PowerShell and unknown-host PowerShell
requests deny on every OS with the fixed reason `PowerShell host contract is not
enabled`. The retained guidance suffix is unchanged. A command must be a JSON
string; missing commands, argv, wrong types, duplicate keys, invalid UTF-8 and
unpaired surrogate escapes retain the fixed malformed-envelope denial. Only
PowerShell envelopes receive the separate 64 KiB raw and 40 KiB decoded-source
ceilings; shared Bash, file and patch budgets are unchanged.

Named tightening: `m5e-unknown-windows-shell-contract` (deliberate-tightening).
On Windows, otherwise unknown tools carrying a `command` field are unknown shell
contracts and deny with the existing `shell requests are unsupported on Windows`
reason. The explicit names `Shell`, `shell`, `CMD`, `Cmd`, `cmd`, `cmd.exe`,
`powershell`, `powershell.exe`, `pwsh`, `pwsh.exe`, `exec_command` and
`shell_command` also deny without a command. Other unknown tools retain no
decision, and Unix unknown-tool behavior is unchanged. No agent-supplied shell
field or source syntax selects a dialect. Native Windows Bash strings and argv,
including Codex Bash, retain their existing denial.

Production PowerShell routing remains disabled. An unexported function seam can
be populated only by tests; only validated Windows Claude `PowerShell` events
can reach it. Unix and Codex cannot reach that adapter. No environment or
request field enables it. Synthetic routing tests and cross-compilation do not
establish a verified host contract or fail-closed host protection. The frozen
Bash guard, matchers, manifests and Bash divergence inventory remain unchanged;
PowerShell cases are adjacent Go tests, not new Bash inventory rows.

## M5e PowerShell classifier core

The unwired `internal/hook/ps` classifier denies everything outside its literal
subset. These named rules apply when a test adapter consults it; production
routing still denies every PowerShell request.

Named tightening: `powershell-literal-grammar` (deliberate-tightening). Backticks,
adjacent quoting, numeric-looking bare words, expansions, subexpressions,
here-strings, splatting, call and dot-source operators, `--` and `--%`, `&&`
and `||`, active `#requires` directives, signature blocks, Unicode quote and
dash substitutes, non-ASCII bare-token bytes and control characters deny. Block comments
end at the first `#>`, as in PowerShell, and any `<#` inside a block comment denies
(native oracle finding, run 40407877597).

Named tightening: `powershell-exact-binding` (deliberate-tightening). Unknown
commands, module-qualified names, abbreviations, common or unmodeled parameters
(for example `-Stream`, `-Encoding`, `-Filter`, `-Include`, `-Exclude`,
`-Recurse`), duplicates, conflicting sets, `ForEach-Object` member names,
`-Begin`, `-End` and `-Parallel`, and implicit property binding deny. Only the
fixed alias table is recognized.

Named tightening: `powershell-literal-anchoring` (deliberate-tightening). File
operands join the validated native cwd without shell expansion and without
cleaning away dot-component witnesses. Operands starting with `~` or `$`, or
containing `${`, wildcard characters `* ? [ ]`, colons outside a drive-absolute
prefix (provider, drive-relative and alternate data stream forms), device names,
or trailing dots and spaces deny. Write destinations require both read and
configuration-write protection checks.

Named tightening: `powershell-certified-streams` (deliberate-tightening). Only
literal or certified public content feeds modeled consumers; redirects cannot
erase an upstream denial, duplicate or overlapping streams deny, and `Copy-Item`
and names-only enumeration also require a metadata certification callback.

Named tightening: `powershell-analysis-failure` (deliberate-tightening). The
40 KiB source, 4,096-token, 2,048-node, 256-word and four-level caps, deadline
checks across scan, parse and walk, and fixed panic denials keep incomplete
analysis from allowing. Denial reasons never contain source text.

## Arithmetic expansion operands

The Go arithmetic walker denies any expansion-bearing operand, including command
substitutions, parameters, backquotes and nested arithmetic expansions. Bash can
recursively evaluate the resulting text and expand array subscripts within it;
classifying the apparent substitution command or its currently known scalar value
cannot certify the arithmetic expression. The rule covers arithmetic expansions
and commands, let, integer declarations (including integer array elements and
later assignments to possibly integer variables), array assignment and parameter
indices, substring offsets and lengths, numeric [[ ]] comparisons and all three
C-style for clauses. Literal arithmetic and bare names
retain their normal checks, including bounded inspection of stored expressions.
Possible integer attributes are retained conservatively across branches and copied
with child analysis state, so a later assignment cannot lose its arithmetic role.
Array compound-assignment indices now use that same arithmetic walker. Ordinary
non-integer array element values and scalar expansions remain data.

Earlier Go controls that allowed numeric-producing substitutions, numeric-valued
parameter expansions or public-reader substitutions in arithmetic now deny by
this rule. Literal arithmetic commands no longer set generic command uncertainty:
this preserves their allow decision through explicit bash -c argv, including
`((i++))` and `let "i=1+2"`. The literal arithmetic function-body controls
`audit28_t13_review_function_public` and `audit28_t13_review_function_public_argv`
now match Bash's allow and no longer require divergence rows. Whole double-quoted
decimal constants in arithmetic commands and C-style loops also retain literal
proofs, including indices and function bodies. Single-quoted operands and other
unsupported or malformed arithmetic framing still deny.

The retained Bash guard allows arithmetic expansions with variable or
numeric-producing substitution operands. It also allows the synthetic printed
subscript operands in integer declarations, assignment and parameter indices,
slices, numeric comparisons and some C-style for clauses. This is a Bash-only
coverage backlog, not a change to the shipped guard or an installed-host claim.
The v0.2.2 comparison uses commit `68b2cf8` in a separate temporary worktree;
all candidate commands are synthetic JSON data and are never executed.

### Arithmetic writer bindings

Integer attributes also apply to for-loop items, read, mapfile/readarray,
printf -v, getopts and writes through namerefs. These binds reach the shared
arithmetic rule before an uncertain value can be accepted. Literal loop items
remain certifiable; unmodelled builtin results are indeterminate for possible
integer targets, even when the supplied format or input looks numeric.

For ordinary variables, these writers invalidate the target's arithmetic value
and stale scalar/loop proofs without denying ordinary data use. Default REPLY
and MAPFILE targets, builtin option arities and printf's format boundary are
retained. Unknown target names invalidate bare-identifier arithmetic proofs,
not numeric-only expressions. Expanded declaration operands retain identifiable
target prefixes; unresolved declaration options deny because they can enable -i
and supply assignments. This does not depend on generic arithmetic-command
uncertainty. Literal controls such as i=0; ((i++)) remain allowed.

Nameref targets retain bounded alternatives and possible integer attributes,
including integer declarations reached after the reference definition. Bind-time
subscripts use the arithmetic rule. Unresolved references and untracked binds
invalidate arithmetic proofs instead of borrowing a prior literal value. Child
analyses copy the reference and unknown-binding state; alternatives are retained
conservatively across branches, rather than cleared by later writes.

Independent runtime witnesses on Bash 5.3.9 used disposable HOME/work roots and
an explicitly synthetic .env file. All nine tested binding families opened that
fixture both on integer binds and during later bare-identifier arithmetic.
The read-array witness preserves the whole field with empty IFS. Separate
expanded declare/export/local witnesses also opened the fixture during later
bare-identifier arithmetic. These runtime witnesses are separate from
adapter/corpus command strings, which remain JSON
data only. They do not establish installed-host protection or other Bash versions.

The arithmetic-writers corpus below adds named directional comparisons to the
existing divergence gate. A Go allow cannot be classified as a tightening, and
literal/data controls must agree with the retained Bash guard.

| Writer cases | Category | Reason |
| --- | --- | --- |
| `arithmetic-writers_writer_read`, `arithmetic-writers_writer_read_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_read_array`, `arithmetic-writers_writer_read_array_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_read_default`, `arithmetic-writers_writer_read_default_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_read_dynamic`, `arithmetic-writers_writer_read_dynamic_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_mapfile`, `arithmetic-writers_writer_mapfile_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_mapfile_default`, `arithmetic-writers_writer_mapfile_default_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_readarray`, `arithmetic-writers_writer_readarray_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_printf`, `arithmetic-writers_writer_printf_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_printf_attached`, `arithmetic-writers_writer_printf_attached_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_printf_dynamic`, `arithmetic-writers_writer_printf_dynamic_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_getopts`, `arithmetic-writers_writer_getopts_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_declare`, `arithmetic-writers_writer_declare_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_export`, `arithmetic-writers_writer_export_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_nameref`, `arithmetic-writers_writer_nameref_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_nameref_dynamic`, `arithmetic-writers_writer_nameref_dynamic_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_wrapped_read`, `arithmetic-writers_writer_wrapped_read_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_wrapped_printf`, `arithmetic-writers_writer_wrapped_printf_argv` | deliberate-tightening | Untracked writer results cannot certify later bare arithmetic identifiers. |
| `arithmetic-writers_writer_unknown_options`, `arithmetic-writers_writer_unknown_options_argv` | deliberate-tightening | Unresolved declaration options can enable integer evaluation and bind an uncertified value. |
| `arithmetic-writers_bind_integer_for_positional`, `arithmetic-writers_bind_integer_for_positional_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_read`, `arithmetic-writers_bind_integer_read_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_read_array`, `arithmetic-writers_bind_integer_read_array_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_mapfile`, `arithmetic-writers_bind_integer_mapfile_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_readarray`, `arithmetic-writers_bind_integer_readarray_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_printf`, `arithmetic-writers_bind_integer_printf_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_getopts`, `arithmetic-writers_bind_integer_getopts_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_nameref`, `arithmetic-writers_bind_integer_nameref_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_later_nameref`, `arithmetic-writers_bind_integer_later_nameref_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_nameref_read`, `arithmetic-writers_bind_integer_nameref_read_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_unknown_options`, `arithmetic-writers_bind_integer_unknown_options_argv` | deliberate-tightening | Unresolved declaration options can enable integer evaluation and bind an uncertified value. |
| `arithmetic-writers_bind_integer_printf_repeated`, `arithmetic-writers_bind_integer_printf_repeated_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_read_initial_default`, `arithmetic-writers_bind_integer_read_initial_default_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_nameref_index`, `arithmetic-writers_bind_nameref_index_argv` | deliberate-tightening | A bound reference uses an unknown arithmetic subscript. |
| `arithmetic-writers_bind_nameref_unknown_literal`, `arithmetic-writers_bind_nameref_unknown_literal_argv` | deliberate-tightening | A possible integer or nameref target binds an uncertified value. |
| `arithmetic-writers_bind_integer_wrapped_declare_read`, `arithmetic-writers_bind_integer_wrapped_declare_read_argv` | deliberate-tightening | Transparent declaration prefixes retain the possible integer attribute before an untracked bind. |
| `arithmetic-writers_bind_integer_wrapped_typeset_printf`, `arithmetic-writers_bind_integer_wrapped_typeset_printf_argv` | deliberate-tightening | Transparent declaration prefixes retain the possible integer attribute before an untracked bind. |

## Interpreter metadata lifetime

Interpreter literal children share their parent's bounded metadata snapshot,
interpreter-name results and Git configuration-write proofs. Initialize caches on
the parent before constructing children so lazy allocation cannot create a fresh
cache for every repeated literal. Command state and environment assignments remain
child-scoped. Configuration proof keys retain raw names, cwd and effective XDG and
global paths; live Git roots are checked before cached proofs. Lookup failures
remain denials, and a fresh analysis gets fresh metadata. This is a per-analysis
snapshot, not filesystem race protection.

The audit 24 Windows boundary regression reached repeated configuration-write
metadata work through full literal command dispatch, despite caching the ordinary
protected-file callback. A simulated 20 ms resolver cost now verifies the exact
256-literal and mixed-literal controls across inline, heredoc, here-string, pipe
and argv inputs without sleeping or enlarging the two-second policy deadline.
Final decisions report deadline exhaustion as indeterminate even when a caller
has supplied a more specific interpreter role reason. Native Windows CI and host
protection remain separate gates.

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
- P17 checks known-command suffixes and shell-like arguments of unmodelled wrappers,
  recognizes versioned shell names and option clusters around `-c`, and analyzes
  fish initialization and coprocess bodies. Scriptless shells and sudo login or
  shell mode without a command deny. Git commit messages remain operands, not
  shell text, because Git is explicitly modelled.
- P15 rejects non-read-only commands that touch Git configuration paths,
  including directory options and in-place sed or perl abbreviations. Write
  targets with unknown variables or globs, and relative targets after ambiguous
  directory changes, deny. Literal assignments and HOME or XDG home paths are
  resolved before deciding. P1e denies `git submodule foreach` outright.
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
| `audit-cases7-2`                                                                                                                                                                   | deliberate-tightening | A symlinked ancestor can reach an actual credential file before `..`; a final-symlink alias exception cannot certify that input.                                                             |
| `audit27_s4_preanalysis_deadline` | deliberate-find-shim | Injected stalled jq denies in Bash; Go has no jq subprocess and checks deadlines independently. Applies to both adapters. |
| `active_safe_command`                                                                                                                                                              | deliberate-tightening | `$c package.json` does not establish the executable or its input and output roles.                                                                                                           |
| `deep_safe`                                                                                                                                                                        | deliberate-tightening | Six nested `shell -c` layers exceed the Go analysis depth and deny.                                                                                                                          |
| `audit6_sed_comment`, `audit6_sed_text_line`, `audit6_sed_insert_line`, `audit6_sed_change_line`                                                                                   | deliberate-tightening | GNU sed reads these as a comment or as a/i/c text, so Bash allows them; Go denies any script whose later commands follow a comment or text command on one line.                              |
| `policy_v2_sed_script_clean`                                                                                                                                                       | deliberate-tightening | A `-f` script file holding `code` is a final one-line `c` command to GNU sed; Go certifies only scripts whose file text matches the safe subset exactly, so it denies.                       |
| `grep_find_exit`, `grep_find_exit_count`, `grep_timeout`, `grep_timeout_count`, `rg_find_exit`, `rg_timeout`                                                                       | deliberate-find-shim  | Bash denies when the injected `find` exits or times out. Go does not execute `find`; its walk errors, permissions, loops, budgets, and deadlines deny under dedicated fault-injection tests. |
| `unresolved_file_safe`, `unresolved_listing_safe`, `unresolved_literal_safe`, `unresolved_no_eval`, `unresolved_positional_safe`, `unresolved_redirect_safe`, `unresolved_wc_safe` | deliberate-tightening | Unknown parameter or substitution output cannot certify a non-protected content-producing input. The analyzer never executes a substitution to decide.                                       |

Audit 28 adds these exact retained Go-stricter controls on both adapters. They
never permit a Go allow where the shell suite requires deny.

| Cases | Category | Reason |
| --- | --- | --- |
| `audit28_t13_compound_time_end_public` | deliberate-tightening | Go retains its conservative `time --` framing denial for an arithmetic command. |
| `audit28_t13_valid_nested_loop` | deliberate-tightening | A command substitution in the C-style loop initializer is an expansion-bearing arithmetic operand, even when it prints a number. |
| `audit27_s16_nested_parameter`, `audit27_s16_nested_parameter_shell`, `audit27_s16_nested_command`, `audit27_s16_nested_command_shell`, `audit27_s16_nested_arithmetic`, `audit27_s16_nested_arithmetic_shell`, `audit27_s16_nested_parameter_command`, `audit27_s16_nested_parameter_command_shell` | deliberate-tightening | Nested parameter, command and arithmetic expansions cannot certify a literal arithmetic operand, including when their apparent result is numeric. |
| `audit27_s16_legacy_nested`, `audit27_s16_legacy_nested_shell`, `audit27_s16_legacy_command`, `audit27_s16_legacy_command_shell` | deliberate-tightening | The same expansion-operand rule applies to legacy `$[ ]` arithmetic. |
| `audit28_t13_review_single_quoted_number_public`, `audit28_t13_review_single_quoted_number_public_argv` | deliberate-tightening | Single-quoted arithmetic operands retain the base conservative framing denial, including literal constants. |
| `audit28_t13_review_quoted_child_public`, `audit28_t13_review_quoted_child_public_argv` | deliberate-tightening | A double-quoted command substitution is still an expansion-bearing arithmetic operand. Even numeric-looking output is indeterminate under the shared arithmetic rule. |

## M2.1 over-denial review

This review preserves the existing output-based search boundary from audits
14 to 16 and 24. Quiet search status is a one-bit match oracle, filenames with
matches also expose match bits, and counts expose more. Existing grep/rg quiet,
count and filenames-only exemptions explicitly allow that information. They are
not a promise of zero information about protected contents. Extending an existing
quiet/names-only exemption is not appropriate for pattern-file inputs, arbitrary
preprocessors, content output or JSON output that can carry matching text.

| Case | Decision | Reason |
| --- | --- | --- |
| `git grep --no-index -q T .env` | Fix over-denial (merged in #10, CI green) | The explicit-file quiet mode prints no contents, consistent with existing grep/rg quiet and Git filenames-only policy. Git count-only behavior is unchanged. Protected `-f` inputs, pager execution and unknown options still deny. |
| `python3 -m env` | Fix over-denial (merged in #10, CI green) | The module name is not a shell env launcher or a `.env` file input. Keep the interpreter path checks and inspect every later argument normally; dotenv/keyring credential modules and real env printers still deny. |
| `rg --passthru -q T .env`, `rg -l --passthru T .env` | Fix over-denial (merged in #10, CI green) | Passthru changes line selection, not quiet or filenames-only output. Both option orders retain the existing explicit-file non-content exemptions. Passthru without those modes, protected pattern files, preprocessors and content-bearing JSON still deny. |
| `rg -g '{!*.md,*.secret}' T` | Intended conservative denial (merged in #10, CI green) | Bounded brace analysis retains the positive `*.secret` alternative. A negated sibling does not make the whole selector a pure exclusion or a safe narrowing proof. The protective config certificate does not admit positive re-inclusions. |

The last case is a certification limit, not proof that every implementation emits
protected content with that exact config. A disposable ripgrep 15.2.0 probe with
an explicit `.` root selects the synthetic secret without config; with the shipped
`--iglob` exclusions it does not, because those exclusions take precedence over
`-g`. The policy deliberately does not model mixed `--glob`/`--iglob` precedence:
`--iglob='{!*.md,*.secret}'` can re-include the protected fixture, and config
certification continues to require no positive re-inclusions. No glob decision or
protected expectation is weakened. Probes without a path read redirected stdin
in this environment, so they are not filesystem-scope evidence.

Table-driven regressions live in `internal/hook/policy/m21_overdenial_test.go`,
`internal/hook/search/m21_overdenial_test.go` and
`internal/hook/m21_overdenial_test.go`. They use disposable metadata and fabricated
files, cover source and argv paths through both adapters, and never execute the
analyzed commands. Local results and inventory regeneration do not establish
native platform CI or installed-host protection. The retained Bash guard and CLI
are unchanged.

## M2 over-denial follow-up review

| Case | Decision | Reason |
| --- | --- | --- |
| Long conditional `cd` chains | Fix over-denial (merged in #22, CI green) | Canonicalized directory alternatives stay precise up to 128 distinct directories (was 32). A per-directory statement replay budget (`maxFlowWork`, 16384) bounds work at twice the earlier 256-word by 32-directory worst case. Exceeding either bound, the 4096-step bound or the deadline still denies, without collapsing to an unknown cwd. Package-manager workspace proofs keep a separate 32-directory bound (`maxWorkspaceDirectories`), so wide-workspace denials do not loosen. |
| `(( "1" + 2 ))`, `((a["0"]++))`, `for ((i="0";i<"2";a["0"]++))` | Fix literal-quote over-denial (merged in #22, CI green) | Only a whole double-quoted decimal constant is accepted. It contains no expansion output or identifier text to reinterpret. This works in explicit-shell argv and function bodies because the base no longer marks literal arithmetic as generally uncertain. Concatenations, quoted identifiers, separators, escapes, parameter operation words, single quotes and quoted `$(( ))` operands retain denial. |
| `(( "$(printf 1)" ))` and quoted recursive substitution output | Drop earlier allowance | The stricter base arithmetic rule wins: every expansion-bearing arithmetic operand is indeterminate, even if the substitution looks harmless or prints digits. The arithmetic, arithmetic-writer and policy arithmetic matrices remain unchanged. Single-quoted decimal allowances are also dropped to preserve the base's existing conservative denial expectations. |
| `time -- ((i++))` | Retained | The Go parser rejects this framing; unparsed source cannot be certified. |

The fresh default-binary generator removes exactly 16 of the base's 181 rows,
leaving 165. There are no additions or category changes. Each of the following
names disappears once from `guard` and once from `codex`:

- `audit28_t13_review_function_index_public`,
  `audit28_t13_review_function_index_public_argv`: literal double-quoted indices
  are now supported inside the function body, with the base's literal proof.
- `audit28_t13_review_quoted_number_public`,
  `audit28_t13_review_quoted_number_public_argv`: whole double-quoted decimal
  constants now match Bash in shell strings and explicit-shell argv.
- `audit28_t13_review_quoted_index_public`,
  `audit28_t13_review_quoted_index_public_argv`: the same literal-only allowance
  applies to arithmetic array indices.
- `audit28_t13_review_quoted_loop_public`,
  `audit28_t13_review_quoted_loop_public_argv`: literal double-quoted constants
  and indices in all three C-style loop clauses now match Bash.

The `cd` change removes no inventory rows. Single-quoted-number and quoted-child
rows remain named in the table above; all 26 arithmetic-operand tightening rows
and the arithmetic-writer evidence are retained unchanged.

`TestConditionalCDChainCap` covers precise alternatives and both budgets.
`TestArithmeticCommandQuotedOperands` covers literal quotes and denied expansion
shapes. `TestOverDenialFollowupAdapters` adds 31 must-deny review commands and
five allow controls, each through both adapters as shell strings and explicit
`bash -c` argv. Protected alternatives at and past the cap, retained failure cwd,
symlinks, pipeline/subshell scope, nested shells, relative container binds,
workspace bounds, recursive arithmetic output, stored operands and unknown
writers all retain denial. Candidates are JSON data only, never executed; every
file is synthetic and below a disposable HOME/work root. These local results do
not establish native platform CI or installed-host protection.

## Permanent synthetic evidence

Audit fixtures are synthetic and permanent in `testdata/hook/audit-cases.json`
and `internal/hook/policy/testdata/audit3.json`. They cover JSON adapters,
Git, archive, directory, find, xargs, parallel, jq, script, and patch decisions.
Fixtures contain fabricated files, symlinks, and generated indexes only. The
variant corpus preserves literal quoting, escaping, brace, and wrapper forms;
active expansions are not made inert, heredoc delimiters are not changed to
disable substitution, and invalid arithmetic rewrites are excluded.

## Measurement and regeneration

The default path uses bounded AST analysis with envelopes up to 1 MiB plus
framing overhead. Ordinary shell text has an 8 KiB limit; inert heredoc bodies
are excluded from that text limit but capped at 1 MiB overall. Word, brace, recursion, glob, and scan limits remain
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

## Audit 10 addenda: Go hook

The Go policy now treats attached Git tokens in non-reader operands and inline
interpreter text as protected, and normalizes command-text Git directories and
separate gitdirs for write checks. Shell `-c` option parsing stops at `-` or
`--`, nested wrappers inspect command slots and option values, and interactive
launchers without certifiable command text deny. `git submodule foreach` and
unchecked `git apply` deny; a cwd listing piped to `xargs echo` denies only
when its scope contains a protected file.

Audit 10b distinguishes strict execution slots from best-effort ordinary
arguments. Invalid shell syntax in titles, prose, JSON, SQL, and label filters
is not a reason to deny; command slots such as `npm exec -c`, `make --eval`,
`rsync -e`, and `gh alias set !...` must be certifiable. The `find` read-only
allowlist excludes output-to-file primaries, and names modified after a static
assignment no longer certify a write target. Synthetic fixtures under
`internal/hook/policy/` and `internal/hook/paths/` pair the denials with
ordinary Git metadata, safe file names, and public command forms. These are
policy checks, not evidence that the installed Bash hook was replaced.

## Audit 11a and 11b: Go hook

Git configuration writes now include the destination itself, both bare and
separate gitdirs, the effective working directory, attached destination options,
and roots created by `git init` or `git clone` within the command. `git apply`
passes only explicit check and summary modes with options from the reviewed
allowlist; templates and command-running Git config do not pass. Static write
variables are invalidated by subsequent identifier uses and indirect assignments.

Make recipe and stdin sources, npm and npx call options, alias shells, launcher
stdin, and abbreviated or clustered command slots are denied when execution
cannot be certified. Heredocs fed to interpreters are not inert data. A command
substitution containing only `cat` of an inert quoted heredoc is acceptable as
Git or GitHub message data, and ordinary writes of a large inert heredoc remain
acceptable. The Go envelope permits up to 1 MiB of such input; structural
limits and internal failures still deny. The command corpus retains the audited
allowances for public archive extraction, benign build tools, and literal copy
and loop forms. Neither this policy nor synthetic tests assert installed-hook
protection. The xargs reader with a named safe argument file now denies, because
contents of that file are not certified to contain only safe paths.

Additional unreviewed shell-suite divergence names from concurrent audit 11
fixtures cannot be added to the inventory from this scope. Existing reviewed
`sudo_shell_safe` and xargs argument-file permits now tighten under audit 11a;
`heredoc_commit` supplies a protected token in a Git stdin message file and
now denies under the revised P18 body rule; a `-m` cat heredoc substitution
remains a valid inert message and must be permitted.

Quoted shell wildcard metacharacters use private sentinel runes against bounded
native directory entries instead of platform-dependent backslash escaping.
This keeps quoted JSON, label filters, and prose literal on Windows while
retaining unquoted wildcard expansion and protected-name checks. Invalid
Windows fixture names are skipped; Windows runtime CI remains necessary.

## P18 revised: Go backstop

The revised backstop checks protected name tokens in interpreter heredoc and
here-string bodies, literal interpreter code-option values, strict command
slots, and arguments to commands without a classified model. Cat and tee
bodies remain inert only when their output does not target a protected file;
Cat heredocs inside Git commit message substitutions retain their previously
classified data role; Git stdin message-file bodies still undergo P18 scanning.
Existing Git configuration
write checks still apply independently.

Modelled operands retain their role classifications: secret transports,
env-file consumers, metadata tools, Git messages, GitHub titles and bodies,
reader patterns, and copy destinations are not raw-token denials. GitHub
message operands are excluded from generic file-input checks without
excluding other GitHub arguments. The synthetic P18 table covers both
protected inline and unmodelled input and the documented safe forms. Sudo
shell-option clusters continue to deny even with a command argument. The
installed Bash hook remains separate from this Go policy.

## P19 audit 12b Go fixes

The bounded matcher now supports negated and POSIX bracket classes, directory
wildcards, and globstar without treating quoted metacharacters as live on
Windows. Inert heredoc substitutions are restricted to Git or GitHub message
values, not file-option operands. Interpreter inline and stdin text receives
Git directory and path checks, including separate and bare Git directories.
Docker volume sources and GitHub API field-file inputs have file roles; Docker
Compose configuration and dotenv listing are printers. Git configuration
variables assigned in command text, make recipe prefixes and stdin makefiles,
and interactive shell launchers deny. Safe build globs, metadata Git forms,
Kubernetes secret creation, and public recursive grep trees remain available.
`internal/hook/policy/p19_test.go` records these synthetic decisions. These
checks do not execute any of their source commands.

## Audit 13: Go hook

The Go policy now rejects Compose configuration printers, dotenv/dotenvx
printers through named package runners, credential configuration getters, PHP
environment dumps, Docker environment inspection, and Kubernetes secret
output with a Kubernetes printer reason. It denies credential-reading file URLs
and zip inputs without evaluating source commands. Bounded glob expansion and
recursive search check files actually in scope, while Git patterns and code
identifiers are not mistaken for input paths. Ordinary unresolved non-reader
operands, inert empty write arguments, static cwd changes in `&&` chains, and
Docker PID pipelines remain available. Default rg excludes hidden files and
simple root-level exact gitignored names; explicit hidden/no-ignore searches
still deny. Windows native volume glob matching and quoted non-path operands
have focused synthetic tests. Inert large heredocs skip content scans when
their destination is already certified safe; non-inert bodies still receive
protected-name checks. None of this changes the installed Bash hook.

The `credential_glob` synthetic fixture now includes an actual matching home
file. A glob over a missing credential file must allow under audit 13 even if
the previous Bash guard denied its protected-looking spelling; this is a
reviewed flipped expectation, not a weakening of a real protected read.

The retained shell audit-13 fixture for `grep -rn --include='*.ts' foo .`
contains `.secrets/nested.ts` under its reused cwd. Go correctly denies that
read even though the new Bash suite expects allow. A clean fixture without a
matching protected file allows. The Bash fixture or expectation must be
corrected before this case can have honest parity.

## Audit 14 decisions

Git commit/tag stdin message files and GitHub stdin bodies from inert heredocs
are data, not readers. This flips the older `git stdin message body` and
`git commit -F -` prose expectations to allow. Clustered `-am` messages are
likewise data. Explicit search roots are scanned even when hidden; recursively
encountered hidden paths are skipped by default, and `.gitignore` exemptions
require a work tree. The older denied `rg TOKEN src sub` corpus fixture now
contains a visible `sub/app.env`, because its earlier hidden-only `sub/.env`
would be skipped by default. An unmatched private-name glob denies if a later
write could create a protected match, flipping the previous unmatched
`~/.ssh/id_*` allowance. Conditional directory changes retain the original
cwd as an alternative for later statements. Git cached removal, names-only
searches, grep quiet/count output, and env-file consumers do not print values.

Kubernetes `get secret -o custom-columns=...` selectors that target secret
data and curl uploads of unresolved shell variables remain outside the
syntactically certified subset. Neither guard provides containment against
arbitrary transformed output or unobserved process behavior. macOS and Windows
runtime CI remains necessary for native glob behavior.

## Audit 15 Go decisions

R1/R3 and L2 restore environment printers in launcher slots, peel leading
package-manager options and local `run` binaries, and remove npm's argument
separator before analyzing its selected command. Known venv/test/search data
operands retain their non-command roles. R2/R8 analyze substitutions in
unquoted message heredocs and keep interpreter heredocs scoped to their own
statement. R4 derives future protected-name witnesses from the selector's
literal structure, including arbitrary environment suffixes. R6 propagates
success/failure cwd sets once per statement, originally with 32-directory and
4096-step caps; AST word budgets count each word once across alternative
directories. The M2 over-denial follow-up raises the directory cap to 128 under
a separate 16384 per-directory replay budget.

L1 models fd execution as a child consuming the selected names. L3/L4 cover
Kubernetes attached output values and comma-separated resource lists. L5/L6
respect the selected Git worktree roots and effective ripgrep configuration;
unsafe hidden/ignore settings cannot receive the default-skip exemption.
L7 treats funzip as an uncertified archive stdout printer. L8 adds `.envrc`
to path roles and the shipped ripgrep exclusions. O1/O2 keep grep output-only
clusters and explicit-file rg counts/names available. O3/O4 use bounded,
filter-aware walks for tool and shell searches. O5 certifies only pure filtered
find name streams into xargs; formatted, disjunctive or otherwise unmodeled
streams keep the conservative policy. O6 scopes no-index Git grep to its
explicit roots. The older denied-corpus Git root fixtures now contain a
visible `src/app.env`, preserving denied protected reads instead of retaining
an over-denial of a public-only source tree. The old `grep -rl` role expectation
flips to allow because names-only output is not a content read.

W1 classifies Win32 invalid-name, bad-pathname, non-directory and filesystem
invalid-argument errors as absent operand paths on Windows only. Permission
and I/O errors are unchanged. Injected error tests run on Linux; native invalid
filename cases still require Windows CI. R5/R7 and O7-O10 are Bash-specific;
Go retains focused tests for the shared directory and search behavior without
changing the installed Bash implementation from this workstream.

Audit 15 completion also retains parent-directory and symlink checks for
unmatched credential globs such as `~/.docker/c*.json`, in addition to deriving
arbitrary environment-name witnesses from the selector. Repeated fd extension
filters are alternatives: a later public extension cannot erase an earlier
protected extension. Ripgrep JSON output does not gain the explicit-file
count exemption when `--count` appears later in its arguments. Synthetic Go
cases cover these regressions and the two Windows non-path data operands.
The default-search proof accepts simple root-name Git ignore patterns, but a
negation invalidates that proof: dropping `!app.env` after `*.env` could
otherwise certify a file the search really reads. Both plain rg and untracked
Git grep have a permanent synthetic negation case.

## Audit 16 Go decisions and cross-platform regressions

The initial cwd now goes through the same canonicalization as every subsequent
flow state. Previously a future bare/clone Git root retained the original cwd
alias, while a later redirect used the physical cwd and missed that protected
root. A permanent Linux symlink-root reproducer covers all three creation forms.
Unmatched credential-glob witnesses are slash-qualified before the shell callback,
including on Windows, so an absent credential cannot enter the bare-name metadata
exception merely because filepath.Join returned backslashes.

A1 never uses negative glob alternatives as a narrowing proof, including mixed
brace alternatives. Pure exclusions retain the ordinary rg default-scope/config
proof; mixed positive/negative braces cannot reuse a protected config certificate.
A2 normalizes shell negated classes in both selector and filesystem matching.
A3 refuses the simple Git-ignore proof in the presence of .ignore/.rgignore files
at the root, scanned descendant directories or ancestors through the worktree.
Slash-free Git ignore patterns apply below the root as well; nested .gitignore
files refuse that proof rather than silently overriding their negations.

A4 models fd -g/--glob as boolean flags. A5 checks every positional/search-path
root under the effective base directory for both fd execution and fd-to-xargs
streams. Regex selectors without a glob/extension proof scan the whole selected
scope. A6 uses the pattern-derived protected-name test for find name/iname
filters and preserves a failed root proof instead of falling back to scanning
only xargs' cwd. Metadata-only children stay available. Public file symlinks are
checked through their resolved target; symlinked directories remain uncertified.
A7 peels npm x just like npm exec, including package/yes options and its separator.
A11 judges Windows alternate streams by their base file before missing-name
handling, including unnamed $DATA streams; non-Windows colon names are unchanged.

B2 peels Python -m modules while retaining venv/test environment-data roles.
B3 accepts attached rg -tTYPE/-TTYPE with the same policy as separate type values.
B4 adds the Markdown type family. B5 accepts rg quiet output on explicit files
without exempting protected pattern-file inputs. B6 checks a literal DIR/** glob
only within DIR, with the ordinary bounded protected-tree scan. B7 carries
bounded cwd alternatives through brace blocks and if clauses, joined with the
outer cwd instead of replacing alternatives with an unknown directory.

These changes have synthetic Go deny and must-allow regressions. Native Windows
stream behavior and macOS/Windows runner evidence remain CI gates; no installed
hook or host-containment claim follows from Linux tests or cross-platform vet.

## Audit 17 Go decisions and parity evidence

D1 checks the roots supplying listing streams to xargs: every find path,
fd/fdfind root and base directory, ls operand, Git -C directory and rg --files
operand. Static shell expansion is shared with command dispatch. Missing,
dynamic, unmodeled or protected scopes cannot fall back to a clean consumer
cwd. Git repository/index overrides, scope-widening parent/top pathspecs and
transformed or compound listing streams remain uncertified. Modeled wrappers check producer roots before retaining the
existing consumer-scope check. Filtered find/fd proofs still walk matching
physical names, including protected names such as .env.ts; directory symlinks
remain uncertified unless
the explicitly resolved root can be scanned safely. Metadata-only children
remain available, as do public TypeScript find-to-wc and fd-to-gofmt commands.

D2 leaves npx/npm exec call options and yarn exec shell strings out of
safePackageChild. The strict shell-slot analyzer checks separate and attached
call values, including pnpm exec calls and effective yarn/pnpm directory flags.
D4 analyzes background commands without exporting their cwd, preserves the
existing subshell/loop/branch denial coverage, and retains the parent cwd after
a statically zero-iteration while-false loop. The historical audit3 `cd-41`
expectation is a classified class (iii) over-denial correction: `cd .secrets &
paste store` reads the ordinary outer `store`, not `.secrets/store`. Its command
is retained with an allow expectation; new background-cd cases deny actual
protected reads in the outer cwd.

D7 shares fd roles with fdfind before raw operand checks and in pipe proofs.
D8 treats keyring get, including Python module dispatch, as a credential printer;
the existing direct-stash transport exception remains unchanged. D9 checks
.ignore/.rgignore ancestors through the filesystem root, not merely through
.git, and refuses certification if the 128-directory bound is exhausted.
D3 dotted HOME store paths, D5 mixed brace selectors, D6 npm aliases/options and
dotenv environment printers, and D10 option-prefixed package printers already
deny in Go and now have permanent tests. D10 also consumes package-option values
when peeling safe runners, preserving ordinary jest/vitest data operands.

The audit 17 Go table runs shell text and argv-host routes against a fake HOME,
with a shell-realistic missing-bare-operand callback. Dedicated physical-root
and ancestor-ignore tests use disposable metadata only. No probed command is
executed and these checks do not establish installed-host containment or native
macOS/Windows runtime behavior.

## Audit 18 Go package execution and keyring options

pnpm `-c` and `--shell-mode` around `exec` analyze the joined child words as
bounded strict shell source, rather than an executable name. Yarn exec uses
that same joined-source check. npm exec/x and pnpm exec retain workspace
selectors before and after the action, including npm options after child
positionals until `--`. pnpm implicit local-binary execution shares shell-mode
handling, and its workspace-root option resolves ancestor project metadata.
Literal existing workspace directories
are analyzed alongside the invocation directory. Unresolved package names and
filter expressions inspect every possible project directory under the existing
32-cwd, 4096-entry and analysis-deadline bounds. Workspace-root discovery checks
only ancestor marker existence, never manifest contents. Git internals and
installed node_modules trees are not implicit workspace candidates; explicit
path selectors still check them. Unreadable scopes, directory symlinks and
exhausted bounds deny rather than certify an incomplete scan. npm prefix checks
both the selected directory and the invocation directory. Child cwd alternatives
do not flow into subsequent sibling statements. Function definitions check their
bodies without exporting their cwd or nested definitions. Known calls replay
the body with bounded directory alternatives and recursion.

npm script arguments retain their data role after the script name, so a literal
`env` option value is not an environment-printing command. The env script itself
still denies. Keyring consumes backend/path options with their documented arity,
including attached and equals forms, before classifying get. Mode/output
selectors also consume their values without obscuring the action. Python module
execution shares those roles; help and direct-to-stash transport remain allowed.

The retained Bash denial corpus and exact guard/Codex inventories include audit
18, with Linux and Darwin guard inventories updated together. No denial case or
expectation was removed, and no new acceptable divergence was added. The new Go
tests use fabricated paths and values and never execute the probed commands.

## Confirmation audit 19 credential and cwd coverage

G1 protects Kubernetes config, literal inherited or command-assigned `KUBECONFIG`
path lists, gcloud application-default credentials and its default credential
DB/cache directory, Vault and Terraform tokens, Cargo credentials, PostgreSQL
password files, and the user HOME's `.yarnrc.yml`. Matching uses names and physical
path metadata, never credential contents. Project `.yarnrc.yml` remains readable:
project npmAuthToken lines are outside this name-based protection. Static ripgrep
certification requires the additional credential exclusions; custom KUBECONFIG
names cannot be certified by that static list. Content-producing Git checks
indexed names against inherited and command-assigned literal paths using both
the command cwd and worktree root; a prior public index decision cannot erase a
later configured credential witness. Filtered find/fd listing proofs
and fd execution classify selected names against the analyzer's retained literal
KUBECONFIG alternatives, including branch unions and physical aliases. Unfiltered
ls, rg and Git listing proofs check those alternatives over the producer roots.
Filters excluding the configured names and metadata-only consumers retain their
allowances. Explicit names-only searches retain their existing rules.

G2 treats `ack` and `ack-grep` as recursive content searches, not metadata tools.
Their scopes get the conservative grep tree proof, without a Git-ignore
exemption. Clean roots and names-only output remain allowed.

G3 adds cloud, registry, Kubernetes and shell-environment token printers. Known
global option values remain data, never actions. J1/J2 below extend recognition
to unknown and interleaved options without relying on an exhaustive option list. A
literal direct pipe to `docker login --password-stdin`, `helm registry login
--password-stdin`, or validated `secret stash FILE KEY` is allowed. A tee,
intermediate command, alternate stdin, upstream stdout diversion or unsupported
sink cannot establish that exception. These syntax checks do not assert that an
arbitrary child cannot transform or disclose values.

G4 retains the deliberate template exemption: `.env.example`, `.env.sample`,
`.env.template`, and names ending in those suffixes are readable outside protected
directories. Git revision-member reads follow that rule as direct file reads do.
Broad Git selectors such as `*.env*` are allowed with a safe bounded index,
including template-only repositories; a protected index or explicit protected
member still denies. The Bash side must use the same exemption; this is not
permission for Go to be looser than the installed guard.

H1 replays bounded literal eval source in the caller's cwd flow, including defined
function calls and transparent command/builtin prefixes. Directory alternatives
reach following statements, but child-shell and pipeline effects stay scoped.
The former audit3 `cd-27` allowance is intentionally reclassified as a denial:
eval can move the caller into a store before a relative read.

H2 retains unknown cwd alongside replayed alternatives after multiple direct
function directory changes, indirect function directory effects, or a call made
away from the definition cwd. A single direct change at its definition cwd keeps
its precise alternatives. Child-shell, background and uncalled nested-definition
effects do not move the caller. Safe Git log/blame formatting still checks
historical revision-member operands; pattern option values remain inert data.
Doctl verbose flags, including equals forms, do not hide its auth token action.

H4 includes npm global flags before or after exec operands. Operand-free pnpm
script fallbacks avoid workspace enumeration even in wide projects, while still
classifying default environment/token printers. Operand-bearing readers retain
the complete bounded workspace-scope proof and deny if it cannot be completed.

H3 accepts pnpm path selectors only with `./`, `../`, or an absolute path. npm
workspace paths require a regular `package.json`. Other selectors conservatively
check the bounded project directory tree rather than trusting an unrelated folder
with the same name. This is the existing metadata-only fallback, not manifest
parsing; incomplete or over-limit enumeration denies.

Permanent mixed allow/deny envelopes are in `testdata/hook/audit19.json`, with
additional quoted, escaped and wrapper variants for eval and Git in Go tests.
Safe literal eval followed by a public read, including command/builtin and quoted
forms, remains a required allow. Bash certifies the literal source in an isolated
analysis scope without discarding its tracked cwd; dynamic source, shell-state
mutations, and defined function calls still deny. The denied corpus retains
per-case HOME and literal KUBECONFIG path metadata, including physical aliases,
so replay uses the same credential witnesses as the synthetic shell suite.
The directional inventory generator rejects
any Bash-deny/Go-allow outcome rather than recording that split as tightening.

Historical audit 19 directional tightening rows (both now deny in Bash as well;
audit 22 regeneration removes their measured divergence rows):

| Case                                    | Go difference                                                       | Reason                                                                                              |
| --------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `audit19_G3_13_printer_unknown_wrapper` | Deny an unknown launcher's Kubernetes token child                   | The recognized printer argv suffix is not ordinary data under an unmodeled launcher.                |
| `audit19_G1_kube_branch_union`          | Deny a literal configured path after conflicting branch assignments | Branch merging must retain every possible configured credential path instead of clearing the proof. |

## Commit review J1-J4 printer options and shell aliases

J1/J2 match cloud, registry and Kubernetes printer action words in order across
option positions. Known value-taking options retain their data roles. Unknown
option tokens are omitted but their possible values remain candidates, so both
boolean and value-taking readings are covered by the ordered-word match. The
option terminator ends subcommand recognition. This deliberately conservative
classification does not certify arbitrary option values as harmless. Ordinary
AWS S3 listings, gcloud auth listings, Azure account metadata and Kubernetes pod
listings remain allowed. No exhaustive global-option allowlist is needed to
recognize a later printer action.

The J1 direct-pipe exception is unchanged: only a literal single pipe into the
validated docker login, helm registry login or secret stash consumer qualifies.
Intermediate commands, unrelated docker/helm subcommands, redirected stdin and
upstream stdout diversion still deny. Alias printers do not acquire a new
transport exception.

J3 retains bounded literal alias definitions, including definitions replayed by
eval. Definitions containing cd/pushd/popd, eval or unresolved command syntax
make subsequent cwd uncertain. Reader aliases replay as bounded shell source at
the use site with the caller's arguments, assignments and redirects; conditional
redefinitions retain every literal alternative. Recursive alias expansion is
suppressed, as in the shell, and nested alias chains share the existing depth,
word, flow-step and deadline bounds. Definitions in uncalled functions, child
shells, substitutions, background commands and pipelines do not affect the
outer alias scope. Public aliases such as ll='ls -l' retain their allowance.

The named J3 wrapper-cwd tightening (`audit20_j3_alias#6` and
`audit20_j3_alias#7`) also invalidates cwd after `command NAME` or `builtin NAME`
when the live alias has directory effects, including through later-defined
functions or alias chains, or unresolved command syntax. These wrappers suppress
real shell alias expansion; the conservative uncertainty preserves directional
Bash parity rather than claiming the alias executes. Ordinary `command ls`,
`command -v`/`-V` queries and public aliases remain allowed. Redirects and
operands on the wrapped call still receive normal analysis.

J4 preserves Go's precise existing eval cwd flow: a cd inside a subshell or
command substitution cannot move the caller. A subsequent missing bare
credentials operand in the public cwd remains allowed, but the same read inside
the child after its cd denies. Unresolved current-shell eval variables and
arithmetic shell-state mutations retain unknown cwd rather than borrowing the
child-scope exception. Tests and Claude/Codex envelopes use a disposable
HOME with synthetic AWS credentials, never real stores or executed probe code.
These results establish analyzer behavior only, not installed-host containment.

## Confirmation audit 20 envelope and credential follow-ups

K1 requires native absolute envelope cwd and no longer substitutes the guard
process cwd. K2 validates raw argv element types before decoding strings, so null
cannot become an empty argument. K3 preserves the no-decision behavior only for
zero input bytes; whitespace and NUL-only requests receive explicit JSON denial.
K4 rejects invalid UTF-8, raw or command NULs, missing/null shell command fields,
non-string/non-array commands, null argv elements and duplicate keys at every
JSON depth. The existing duplicate-key scanner is retained. Shared malformed
byte fixtures are in `testdata/hook/audit20-invalid.json`, tested through the
input decoder and both Claude/Codex decision routes.

K5 protects `.aws/config` exactly like `.aws/credentials`, including tree and
filtered content searches. Literal inherited AWS_CONFIG_FILE and
AWS_SHARED_CREDENTIALS_FILE paths are matched as singular names, with lexical
and physical aliases. Shell assignments retain path alternatives through branch
unions and share the existing configured-path checks with KUBECONFIG. Assigned
AWS paths containing the native path-list separator deny as indeterminate rather
than being incorrectly split. Static ripgrep certification requires the AWS
config exclusion and cannot certify arbitrary inherited AWS path names. Ordinary
AWS configure list, S3 listings and get-caller-identity remain allowed.

L1 interpreter inline code, heredocs, here-strings and oversized heredoc bodies
use the shared name/metadata classifier with the interpreter cwd, HOME and
retained literal configured paths. Bare filename literals count, not only
slash-qualified paths. Redirect bodies see literal credential-path assignments
on their recipient before analysis. No source is evaluated and no credential is
opened. Public source files and project Yarn configuration retain their rules.
The L1 decoded-producer check also inspects shell quote/escape-decoded arguments
and here-strings on the upstream AST, including command/builtin wrappers, before
interpreter pipeline exceptions. It retains the raw-source check and shares the
existing word and deadline budgets. These are positive credential-name witnesses,
not execution of producers or a general stdout evaluator. Permanent tables cover
Python, Node, Ruby and Perl, relative and `./` names, inherited and assigned
Kubernetes/AWS paths, literal quoting variants and public source allowances.

L2 historical revision-member checks use configured-path-aware classification
before safe log/blame/diff formatting returns. Summary flags cannot turn a
protected historical blob operand into metadata-only input. Pattern/message
option values remain data, and public template member reads remain allowed.

L3 adds ECR public login passwords, ECR authorization tokens and STS assume-role,
assume-role-with-web-identity, assume-role-with-saml and get-federation-token.
Their option-independent classification and direct transport rules are the same
as J1/J2. Tests also cover color off, no-cli-auto-prompt, gcloud billing project,
doctl -c and Kubernetes request timeout options. All evidence is synthetic
analyzer input, not a claim of host containment or installed protection.

Windows CI follow-ups keep native drive-qualified absolute paths independent of
uncertain cwd. Configured-path comparison canonicalizes the existing physical
prefix through EvalSymlinks on Windows, which expands 8.3 aliases consistently
with cwd and search-root normalization. Missing final components retain that
canonical anchor; metadata errors other than absence still deny. The shared
helper has OS-independent injected-resolver tests. Sed file slots admit a
forward-slash drive prefix and literal tilde characters (including 8.3 names),
without accepting colon as a general script delimiter or changing backslash
escape grammar. Existing strict Windows function/index/search/sed tests remain.

### Audit 20 interpreter stdin and inherited-index review

Interpreter stdin provenance now follows the normal bounded command dispatcher
through execution wrappers, literal aliases, subshells and brace groups. It is
scoped to the recipient, not later independent commands. Source expansion stays
anchored at the producer or redirect cwd; filename classification uses the
interpreter's effective cwd, including env chdir and grouped directory changes.
Here-strings and expansion-enabled heredocs use bounded, non-executing scalar
expansion before the shared classifier, while quoted heredocs stay literal.
Raw-source witnesses remain checked. Unknown or unsupported executable redirect
expansion denies as indeterminate rather than becoming an empty body.

Interpreter prose with a component longer than 255 characters is not sent to
filesystem metadata checks as a plausible filename. Lexical and configured
credential witnesses still deny, even in oversized names, and metadata failures
for plausible paths still fail closed. Public long-text controls cover inline,
heredoc, here-string and decoded-producer forms.

The Git index lexical-only shortcut also requires both inherited singular AWS
credential variables to be empty. Configured-path callbacks retain singular AWS
names (including literal colons on supporting filesystems), cwd/worktree anchors
and protected-name checks. Synthetic v2/v3/v4 indexes cover configured entries
and public-file controls for both AWS variables. Permanent table regressions are
in `internal/hook/policy/audit20_stdin_review_test.go`; none execute the probed
commands or read credential contents. The directional parity requirement still
applies; these tests make no installed-host protection claim.

### Audit 20 cross-platform CI follow-ups

Configured-name comparison retains the deepest resolvable physical ancestor when
an oversized suffix cannot be looked up (ENAMETOOLONG, or Windows
ERROR_FILENAME_EXCED_RANGE). This preserves configured witnesses across symlinked
ancestors such as macOS /var and /private/var even when a component exceeds the
filesystem limit. Ordinary physical resolution and the Windows existing-prefix
resolver still return these errors to their fail-closed callers. Linux-runnable
regressions use a disposable symlink and 300-byte components, check both alias
directions and subtree coverage, and retain unrelated public-file controls.

Existing-prefix canonicalization has a 128-attempt bound to limit metadata work
independently of path depth and spelling. Exhaustion returns an error, not an
allow. Injected-resolver tests cover relative parents, deep suffixes, drive roots,
volume-relative names, UNC and extended-length paths without contacting shares.
Relative-parent inputs converge under filepath.Dir in the baseline tests too;
these tests do not demonstrate a Windows ancestor loop. The existing symlink-hop
limit and strict metadata errors remain unchanged.

All hook subprocess launches are synthetic test evidence, not analyzer behavior.
GNU sed evidence and disposable Git fixture creation use context deadlines, empty
stdin unless a test explicitly supplies synthetic sed source, captured output and
a bounded inherited-pipe wait. Git fixtures also disable terminal prompts, pagers
and optional locks, retaining isolated config, hooks and signing. A self-test
checks synthetic stdin EOF, stdout/stderr capture and deadline termination. The
GNU sed tests are Linux-only, so their previously unbounded commands do not
establish the cause of the Windows stall. The retained Windows CI log contains
no active test name or timeout stack; it is insufficient to attribute that stall
to ancestor traversal or a child process. Windows policy tests now run separately
with verbose subtest output, all-goroutine timeout diagnostics and a 25-minute
test deadline, within a 60-minute Go job bound. Native Windows CI evidence is
still required; Linux tests do not establish that the runner hang is resolved.

### Audit 21 printer grammar and child roles (M2, M3)

Go printer roles share one option normalizer for global and interleaved options,
long equals forms, attached short values and short flag clusters. Known option
values are data; unknown option values remain possible action words. Security
password flags and clipboard output flags use cluster membership, not whole-argv
spelling. Security -g remains an unconditional stderr denial. Docker inspect and
Compose config, gh oauth_token, op, wallet and npm global config output use the
same roles through launchers and literal interpreter command strings. Repeated
output-option aliases cannot erase an earlier credential-output witness. The
explicit Docker image-inspect and public-format controls remain readable; an
unknown global option cannot supply the image-only proof. The boolean op --cache
flag cannot consume an action word. A global -- cannot hide later positional
actions or subcommand flags; harmless post-terminator operations remain allowed.

Launchers consume their own option grammar and dispatch the actual child through
ordinary command analysis, rather than a partial printer-name list. Scheduling
priority, CPU mask, timeout duration and flock lock operands are not children.
Malformed scheduling syntax denies instead of discarding a possible printer.
Watch checks both literal child argv and joined shell source; --exec retains argv
semantics. Watch --differences accepts its optional attached value without
consuming the child command. Generic unknown execution derives printer witnesses from the shared
role classifier. Classified reader operands and documented test/script data are
not recast as launcher commands. Direct credential sink validation is unchanged;
PHP, package config output, gh oauth_token and Kubernetes secret-object output
retain their pre-existing unconditional denials when moved into shared roles.

### Audit 21 command directories and curl inputs (M4, M5)

Yarn --cwd joins the existing package directory model. Sudo chdir and env chdir
continue to scope their child; make directory options and Compose project
options now anchor their own reader/command analysis. A command's directory does
not change the next shell statement. Repeated package, env, sudo and Compose
directory options stay anchored at the original process cwd; make applies its
-C options sequentially, including -sC and attached cluster values. Required and
optional make option arities prevent letters inside file, include and scheduling
values from becoming directory switches. Sudo retains its conservative
original-cwd alternative. Tests cover HOME credential basenames, repeated options
and public siblings.

Curl file-input syntax is normalized before shared credential metadata checks:
@ data and JSON inputs, --write-out/-w @ format files, form uploads/content
files, upload/config options and local file URLs (including URL decoding and
native drive paths). Quoted form filenames retain commas and semicolons;
headers=@ is another file input even on a literal-valued field, while filename=
remains metadata. Literal format strings are data. Known payloads,
form-string literals and output destinations retain their data roles. Physical
credential aliases and HOME paths use the ordinary resolver. Unknown curl
options retain generic positive-witness checks; unsupported command-like syntax
cannot become an allow merely because curl's known inputs have a grammar.

### Audit 21 executable interpreter bodies (M6)

Lua and Rscript join the interpreter stdin and inline-code paths, including
os.getenv and Sys.getenv witnesses. Executable bodies inspect independently
quoted literal strings and backticks with the same credential-printer roles as
shell calls, including declare -p. Modeled literal launchers use the ordinary
bounded child dispatcher with isolated command state. Indeterminate probes of
incomplete launcher text such as "timeout" are not positive printer witnesses.
The probe's recursion limit likewise supplies no witness on its own. Actual
credential-printing children remain denied. These probes never launch source or
a candidate command. File-only programs such as sed keep their file-literal
classifier, without treating an ordinary process.env search pattern as an
environment dump.
Public interpreter-output controls and configured-path cache-scope tests remain.

### Audit 21 per-analysis metadata and Windows CI (M8)

Physical resolution caches Lstat, readlink, canonical-existing-prefix results,
returned errors and raw-path resolution only within an analysis. Raw keys retain
link/.. semantics. Each metadata map has a 4096-entry cap; a full cache resolves
normally rather than certifying a miss. Interpreter filename decisions include
cwd and the accumulated configured-credential path set in their key. Caller
metadata callbacks are memoized only within the same bounded analysis. Git
configuration-target metadata proofs also cache raw name, cwd and effective
XDG/global config paths; live Git roots and directory assignments are checked
before consulting this cache. No cache survives the next host envelope, and this
metadata snapshot does not provide
filesystem race containment or sandbox protection.

Synthetic tests compare cached and uncached classification, retain errors,
exercise physical aliases and a fresh analysis, and ensure later configured-path
assignments cannot reuse a public-file result. Linux CPU profiles identify
ConfiguredProtected -> physicalOrClean -> physical/Lstat as the producer hot
path (4.30 seconds cumulative in ConfiguredProtected, 57.10% of sampled CPU).
A serial Linux rerun against HEAD 8dcb901 and the revised tree reduced
TestAudit20DecodedInterpreterProducers from 6.877 to 3.125 seconds (both CPU
profiled), and TestGuardDeniedCorpus from 99.604 to 63.950 seconds (uncached test
runs). The revised corpus covered 48,017 variants from 2,461 Bash-deny cases
with zero allows. Native Windows runtime and speedup still require CI evidence;
cross-vet is not a Windows runtime test. The Windows policy step temporarily has a
45-minute step limit and a 40-minute Go test deadline inside the existing
60-minute job bound.

Permanent regressions are in internal/hook/policy/audit21_test.go,
internal/hook/roles/audit21_test.go and internal/hook/paths/metadata_test.go.
The internal/hook/audit21_test.go replay uses testdata/hook/audit21.json for both
host decisions with a disposable HOME. These tests do not install a guard or
establish installed-host protection. Existing corpus expectations are retained.

### Audit 21 integration parity (M1 to M6)

Failed Go shell parses now deny regardless of raw risk substrings. Missing sudo
option values, oversized brace alternatives and reserved ANSI-C separator bytes
also deny before inert-output exemptions. Supported literal ANSI-C escapes keep
their data role, including unknown escapes whose backslash remains literal.

GNU Parallel distinguishes complete joined shell templates from explicit input
lists and accepts attached job counts. Source filenames still receive protected
metadata checks for reading templates; ordinary printf, echo and secret show
children retain their data/metadata roles through xargs and Parallel. Find's
existing protected-name metadata proof remains narrower. External
time options parsed as a shell time clause use the utility's normal child grammar.
Make's option-value boundaries keep letters in attached filenames from becoming
printer flags, while attached makefile inputs are checked at the effective cwd.
Docker build/load file operands use shared protected-path checks. Docker
--env-file consumers keep their documented non-printing exemption. Single-action
keyring and secret-tool commands stop resolving actions before data operands,
without letting an unknown global option hide lookup/get. Versioned and hyphenated
Lua/LuaJIT names share inline, stdin and producer checks.

These groups resolve to the retained Bash decisions, not new deliberate Go-stricter
rows. The historical `audit-cases6-7` clustered-xargs protected argument-list
case now denies in both guards, so its measured divergence row is removed.
Existing deny expectations are preserved. The M1 inert parse-failure Go
unit expectation is intentionally tightened to match the fail-closed policy.
Integration regressions are in internal/hook/policy/audit21_test.go,
internal/hook/roles/audit21_test.go and testdata/hook/audit21.json.

### Audit 22 shared Go classification and schema (N1 to N6, N8, N13)

Implicit yarn children inherit --cwd through the same fallback directory model
as -C/--dir. Repeated directory options remain relative to the incoming cwd, and
none changes the next shell statement. Explicit exec and implicit child forms
therefore check the same credential basenames and public-file controls.

The shared printer normalizer accepts case-insensitive true/1/yes/on and
false/0/no/off boolean values. Only an explicit false spelling removes that
option's witness; invalid values and another enabled occurrence cannot establish
a non-printing proof. Kubectl secret output covers JSON/YAML, JSONPath, template
and custom-column families, including file-backed and as-JSON variants. Resource
names and table output remain metadata, and public resources are not credential
printers solely because of their output format. Op item get --otp and signin
--raw use the ordinary account-option and launcher classification. Existing
single-direct-pipe stash/login allowances are unchanged; kubectl secret content
keeps its pre-existing always-deny transport policy.

Executable interpreter bodies recognize complete literal argv launch signatures
for Python subprocess and os.execv/execvp families, Node spawn/execFile families,
and Ruby/Perl system or exec calls. Literal elements retain argv boundaries and
use the ordinary isolated child dispatcher, including printer options, launchers,
reader operands, configured paths and cwd. Python exec's selected executable is
not confused with its argv[0] label. The bounded lexical scan does not execute or
evaluate language source, infer variable lists or concatenations, or treat an
ordinary standalone array as a launch. Existing shell-string, file-literal and
environment witnesses continue independently. Public child argv and non-printing
options remain readable. This positive-witness coverage is not general language
containment or a sandbox.

The audit 22 review carries the recipient interpreter identity through inline,
heredoc and literal-producer stdin paths. Comment syntax is language-specific:
Python floor division and Perl defined-or cannot truncate executable source, and
Node regex literals containing # remain data rather than hash comments. Bounded
slash-regex scanning retains escaped delimiters and character classes; genuine
line/block comments and public-command controls remain non-witnesses. Positively
identified argv calls retain indeterminate or structurally uncertain child
results and deny at the dispatch recursion bound. Arbitrary standalone strings
still require concrete role witnesses, so incomplete launcher prose stays allowed.

Named tightening `audit22-bare-interpreter-argv`: Go also recognizes bounded,
parenthesis-free Ruby/Perl system and exec literal lists ending at a semicolon,
newline, closing brace or end of source. These were a shared class (i) N6 gap,
not a directional-parity blocker under P22; Go now denies their credential
children even if the retained Bash guard has not acquired this coverage. Public
children, literal prose and unclassified concatenations keep their prior roles.
Permanent review tests are internal/hook/policy/audit22_review_test.go and the
N6 review cases in testdata/hook/audit22.json. No prior expectation is weakened.

Curl's file-input normalizer accepts file:/ paths as well as file:// URLs,
including --url and --url= operands, percent-decoded paths and physical aliases.
Native drive URLs retain their Windows conversion. Payloads, --data-raw and
public file URLs keep their data/public-input roles.

Envelope validation rejects unpaired UTF-16 surrogate escapes before Go's JSON
decoder can replace them with U+FFFD, including in unknown fields and keys. Valid
surrogate pairs, literal replacement characters and escaped backslashes remain
valid. Read/Edit/Write/MultiEdit require a nonempty string file_path;
NotebookEdit requires a nonempty authoritative notebook_path; an unrelated
file_path neither substitutes for it nor changes the selected target.
Every supplied optional path, output_mode and workdir field must be a string,
not null, an array or another JSON type. Missing optional Grep/Bash fields keep
their prior defaults; missing or empty tool names still deny. Both host adapters
emit explicit value-free denials for malformed supported envelopes.

The audit 21 makefile arity control remains allowed on Unix. On Windows,
`make -fC$HOME/.aws` names a makefile with an embedded drive colon after HOME
expansion, not a directory option. The makefile metadata check cannot certify
that invalid native path and retains its conservative denial; the test records
this platform-specific outcome without weakening a credential read.

Permanent tests are internal/hook/policy/audit22_test.go,
internal/hook/roles/audit22_test.go, internal/hook/input/audit22_test.go and
internal/hook/audit22_test.go. The last two replay
testdata/hook/audit22-invalid.json; both host adapters also replay
testdata/hook/audit22.json with disposable HOME fixtures. Candidate commands are
never executed. The former file_path-only NotebookEdit allow is now a classified N13 malformed-
envelope denial. The old unrelated-file_path denial becomes an allow because
that field is not a host target; protected notebook_path targets still deny.
Other existing expectations are unchanged. Except for the named
parenthesis-free argv tightening above, these are parity fixes rather than new
Go-stricter decisions. Cross-vet does not establish
Windows or macOS runtime behavior, installed-hook protection, or host failure
blocking; applicable CI and host gates remain required.

The parity handoff keeps configured paths keyed by their environment variable:
plain sequential assignment replaces that variable's prior target, while
conditional, loop and scoped assignments retain alternatives. Application child
analysis restores the parent's configured paths on return, including env and
shell children, while allowing sequential replacement within the child itself. Case arms are all
analysed without making an otherwise literal public reader indeterminate.
Kubernetes values retain native path-list semantics; singular AWS paths stay
whole even when a filename contains the native list separator. File, interpreter,
search and Git-index checks receive those singular alternatives without joining
or splitting them. Per-analysis interpreter cache keys retain both kinds.

Unknown-launcher dispatch now includes every recognized interpreter alias,
including Lua versions and LuaJIT. Attached GH --input operands use the shared
file classifier. Curl preserves unmatched literal file URLs for query/fragment
normalization, but --user-agent values remain data. These close measured
Go-allow/Bash-deny splits or ordinary-syntax over-denials, not new tightenings.

Corpus extraction retains direct-envelope optional fields and their original
JSON types, including malformed workdir values. Corpus fixture directory names
no longer inherit subtest # suffixes, which would turn URL path bytes into a
fragment. Every original case and variant remains, with per-case fixture cleanup.

## Confirmation audit 23: Go directional parity (O1-O5)

These changes close measured Go-allow/Bash-deny decisions from snapshot
7535c5c. They do not weaken an existing denial or introduce a reviewed
Go-stricter divergence. The retained Bash CLI and installed hooks are unchanged
by the Go implementation; synthetic decisions are not host protection evidence.

- O1: Python triple-single and triple-double quoted strings are one opaque
  tokenizer token, including embedded matching quotes, escapes and newlines.
  Subsequent literal argv launches still reach the shared child dispatcher;
  quoted launch text remains data. Static Python prefixes are normalized with
  Python escape rules; unsupported escapes and dynamic replacement fields do
  not supply a fully literal argv witness.
- O2: gh API field-file checks resolve the action through the printer option
  normalizer rather than requiring api at argv position zero. Known global
  option values remain data. Separate and attached -F/-f, --field and
  --raw-field operands retain their protected-file checks with leading hostname
  and repository options. Public fields and non-API commands remain allowed.
- O3: curl file-URL paths reject decoded C0 controls and DEL before metadata
  classification, including tab, LF, CR and NUL. Percent-encoded spaces,
  once-decoded percent signs, HTTP URL paths and literal request data retain
  their public-input or data roles.
- O4: identified literal shell-launch calls and Ruby/Perl backticks use the full
  bounded shell AST policy, not a single argv word or a printer/wrapper subset.
  This includes dotenvx readers, package environment commands and Python module
  printers, as well as shell cwd changes and compound statements. Literal argv
  lists keep argv semantics. Both launch forms share isolated child analysis,
  configured-path metadata, recursion limits and uncertain-decision handling.
  Python os.popen shares os.system's full shell-child dispatch, including
  optional later arguments. Raw, bytes, Unicode and interpolation-free formatted
  Python literals (including supported combined and case-insensitive prefixes)
  supply static arguments with Python-correct escape handling. Raw escapes stay
  raw, bytes retain Unicode escape spellings, and doubled formatted braces are
  literal braces; genuine replacement fields remain unknown. Python/PyPy exec
  evaluates interpreter source, not shell source, so it retains existing source
  checks without supplying a shell-launch witness. Ruby/Perl/Node exec launches
  retain their shell roles. Arbitrary prose retains positive-witness scanning
  rather than full command dispatch; public literal children, ordinary Python
  exec source and child-local cwd changes remain allowed.
- O5: PyPy executable aliases, including versioned names, share Python's inline,
  argv, heredoc, producer, module, comment and literal-token roles. Existing
  Python aliases keep their recognition. Public code and venv creation remain
  allowed while environment dumps and credential-printer children deny.

Permanent tests are internal/hook/policy/audit23_test.go,
internal/hook/policy/audit23_review_test.go, internal/hook/roles/audit23_test.go
and internal/hook/audit23_test.go.
Both adapters replay all 282 cases in testdata/hook/audit23.json with a disposable
HOME and synthetic files. Candidate commands are never executed. Native checks
and cross-vet do not replace applicable macOS/Windows runtime CI or host failure
checks.

### Confirmation audit 23: envelope integration (O6-O9)

Bash validates complete JSON before jq, rejects malformed surrogate escapes and
non-JSON scalar grammar, and checks workdir controls before extraction. Envelope
preprocessing and every successful file-tool exit count against its four-second
decision budget. Shared path normalization stops on budget exhaustion and cannot
certify a public file after normalization fails. The dependency-light no-Perl
path retains strict bounded ASCII JSON with ordinary scalar and whitespace
controls.

Both validators cap raw envelopes at 1 MiB plus 64 KiB, with at most 4,096 keys
globally, 32,768 JSON tokens (including punctuation) and 128 nested containers.
Go counts these before unmarshaling; root objects count as one container and
object keys, colons and commas count as individual tokens. Exact limits allow;
under-byte-cap structural overflows deny. Go also rejects more than 4,096 slash
separators in cwd, file_path, notebook_path, path and workdir before cleaning
redundant components. This deterministic tightening covers excessive-component
paths that exhaust Bash's wall-clock normalizer; ordinary redundant paths allow.
It is not a claim that Go reproduces every host-dependent Bash timing decision.

Permanent boundary and public-path controls are in
internal/hook/input/audit23_test.go and internal/hook/audit23_test.go. The shell
suites retain audit23_o6 through audit23_o9 deny and must-allow controls, including
keys_limit/over, tokens_limit/over, depth_limit/over and both excessive-component
file_path/cwd reproducers. Synthetic dependency delays test Bash's deadline, not
installed host behavior.

The existing Go text-field validator still rejects LF and tab in path fields;
Bash permits those valid filename characters. The new shell public controls
`audit23_o8_workdir_newline` and `audit23_o8_cwd_newline` therefore record a
retained Go-stricter decision in each suite. These four deliberate-tightening
rows do not represent Go allows or newly weakened Bash expectations. The
regressions in internal/hook/input/audit23_test.go keep the Go decision explicit.

### Confirmation audit 24: shared literal fallback and input deadline

These changes close the Go-side P1-P9 and P11 findings without a new reviewed
Go-allow divergence. P10 bounds the shared Bash scanners and the corresponding
Go interpreter scan structure, rather than accepting a faster Go allow after a
Bash scan exhausts its limits.

- P1: literal list-first spawn calls, Ruby positional spawn (including Process
  and Kernel qualifiers and statement syntax), and IO.popen literal argv arrays
  reuse the existing complete child-role dispatcher. Quoted argv is never joined
  into executable shell syntax. Public git/status and metadata children allow.
- P2-P3: Node, Node.js, Bun and Deno share static template-string, comment and
  regex tokenization. Interpolated templates remain unknown as static argv,
  but retain recognized command-prefix witnesses in the conservative fallback.
  String interpolation rules are language-specific: Lua, JavaScript double quotes
  and R do not interpolate Ruby's #{...} or Perl/PHP's dollar expressions. Bun inline flags,
  run with inline flags, Deno eval and stdin bodies use executable interpreter
  analysis. Runtime flags are not discarded as package child options.
- P4: every executable interpreter uses the same broad literal fallback before
  precise argv signatures. A closed whitespace-bearing literal starting with a
  recognized command role goes through full bounded shell policy, even when
  interpolation prevents static argv certification, irrespective
  of its surrounding API. This covers Lua os.execute/io.popen, PHP shell APIs,
  R named/status arguments, Ruby IO/Open3 strings and Perl pipe-open strings
  without maintaining a separate API table for each command family. The same
  metadata/configured-path and environment witnesses remain in force. Recursive
  content grep inside interpreter literals cannot use the current tree as a
  safety proof: earlier interpreter code may extract files before the search.
  This applies even to an initially empty tree; names/count/quiet modes and
  nonrecursive public-file searches retain their non-content/public roles.
- P5: Perl q, qq, qx and qw operators are tokenized atomically with paired or
  same-character delimiters and nested pairs. qx is shell source; qw contributes
  separate literal argv elements. Interpolation does not supply static argv.
- P6: Bun implicit, run, x and exec children and inline runtime code retain the
  package launcher's --cwd or --cwd= directory, anchored at the incoming cwd.
  Leading options are resolved before either runtime-code or child dispatch;
  directory operands are not interpreter source. Invocation cwd cannot escape
  to the next statement. Public filenames and stat operands remain allowed.
- P7: value-less declarations do not assign an empty value or erase credential
  path alternatives, including after a branch join. Configured assignment values
  share bounded scalar expansion with interpreter stdin, without execution,
  splitting, globbing or ~user lookup. Unquoted leading ~ or ~/ and supported
  quoted/unquoted $HOME and ${HOME} use the supplied HOME. Unknown expansions
  deny rather than clearing configured protection. This includes declare and
  export -n, and all three configured credential variables. Sequential explicit
  replacements retain their existing precision.
- P8: lexical protection of cwd-anchored credential operands precedes the bare
  operand existence exception. A missing target or empty store directory cannot
  certify a reader because an earlier extractor can create it. Explicit workdir,
  envelope cwd and tracked cd paths share the rule. Metadata-only and unrelated
  public-file operands remain allowed.
- P9: HOME/.aws is an explicit protected content-search root before rg config
  certification, including an implicit cwd at that root. Filename-only modes and
  certified public/SSH/Kubernetes roots retain their existing behavior. This
  intentionally matches Bash rather than introducing an unrecorded Go allow.
- P10: executable interpreter source shares the retained scanner ceilings of
  8 KiB per literal and 128 separator bytes, before literal policy dispatch.
  Decoded literal records, including Perl qw elements and numeric data words,
  use the same 256-entry ceiling as the Go word budget (stricter than Bash
  extraction at 512 records). Numeric words consume work without becoming
  certified string argv elements.
  This bounds literal work independently of interpreter API or input shape and
  denies the original 200-line, 400-data-word P10 reproducer as well as the
  600-literal forms. Inline, heredoc, here-string, producer and argv paths
  share the limits, with exact-boundary must-allow and exceeded-boundary denials.
  Existing outer shell-fragment and 1 MiB stdin-body limits still apply; a
  large inert heredoc without literal records retains its allowance.
  Here-string quote removal
  decodes escaped unquoted literal bytes before scalar expansion, preserving
  quoted/escaped dollars and tildes without a second evaluation pass. Raw
  serialized stdin keeps file/environment witnesses, not literal scan budgets.
- P11: one shared envelope reader bounds both bytes and elapsed read time. It
  requires EOF within two seconds for both Decode and the initial Decide read;
  complete JSON with an open writer is not yet a complete envelope. Timeout,
  panic, read error and size overflow deny without echoing input. Closed empty
  input retains no-decision behavior. A buffered, private read result prevents
  a late read from emitting another decision. The owner must close an arbitrary
  blocked io.Reader to release its goroutine; the one-shot CLI exits after its
  decision. No installed-host timeout behavior is claimed.

Audit 24 deliberately supersedes older positive-witness-only allowances for
recognized-command literals. Incomplete launcher strings such as "bash -c",
"watch --unknown date" and "parallel --nonall aws", and recognized command text
such as print("dotenvx get"), now deny like Bash even when used as data. The
corresponding audit21/audit22/audit23 tests and envelopes change only from allow
to deny, retaining every command and recording this classified tightening.
Unrecognized prose, standalone non-launch argv data, public interpreter reads,
comments/regex data and complete harmless child commands retain must-allow tests.
Broad launch analysis operates on decoded interpreter source, not serialized
producer shell quotes, so ordinary Perl file-reading source is not mistaken for
an implicit shell command.

Integration closes the review-control splits in the shared Bash classifiers.
Configured assignments resolve active scalar values before caching paths or
checking declaration indirection; export -n options are not variable names.
The shared search parser classifies interpreter literal names/count/quiet modes
before rejecting recursive content searches without a tree proof. Raw recursive
flag matching no longer overrides these interpreter metadata roles. Public HOME
declaration controls and empty-tree metadata controls retain their must-allow
expectations in both adapters, without accepted Go-allow divergence rows.
The Bash normalizer also maps PyPy aliases to Python analysis, normalizes Perl
q/qq/qx/qw operators before literal and argv dispatch, and retains Ruby popen
argv arrays as complete child launches. Paired Perl delimiters scan nested
pairs and escapes within the existing extractor deadline; qx emits shell source,
while qw supplies separate literal argv words. These shared paths preserve
recursive content denial without restoring raw metadata over-denials.

The lexical-before-existence rule deliberately tightens older Bash allows:
`no_file`, `env_chdir_empty`, `audit15_r7_success`, `audit15_r1_data#12` and
`audit15_r1_data#13` in the guard suite, and `cwd_safe`, `audit19_allow#14`,
`audit19_allow#15`, `audit19_allow#16` and `audit19_allow#17` in Codex. The
first group and cwd_safe read an absent protected basename after a cwd change,
including package directory options. The four Codex package workspace controls
have public missing basenames across a conservative directory union that
includes the synthetic protected `.secrets` root (created earlier in that suite). Existing shell expectations stay unchanged; Go denies
rather than assuming these targets remain absent when execution begins.
These are named deliberate-tightening rows, not accepted Go-allow differences.

Permanent coverage is internal/hook/policy/audit24_test.go,
internal/hook/policy/audit24_review_test.go (including an actually empty tree),
internal/hook/search/audit24_test.go, internal/hook/input/read_test.go and
internal/hook/audit24_test.go, plus both-adapter testdata/hook/audit24.json.
All candidate commands remain JSON/analyzer inputs only, with disposable HOME
and synthetic fixtures. Native checks and cross-vet do not substitute for
applicable macOS/Windows runtime CI or installed-host evidence.

## Confirmation audit 25: interpreter extraction and quote boundaries

Replays compare cf6e337 with 008f53c using JSON envelopes, a disposable HOME,
synthetic `.aws/credentials` and `.env` names, and both Go adapters. Candidate
commands are data only. The installed hook and plugin manifests are unchanged.

- Bash changed ``perl -e 'print `grep -r TOKEN .`'`` and the equivalent Ruby
  backtick command from deny to allow. Lua `os.execute([[grep -r TOKEN .]])`
  also changed from deny to allow inline. Go already denied the Perl/Ruby
  backticks, but allowed the Lua body before and after the commit. Bash Lua
  heredocs remained denied by raw bracket/redirect recovery, not complete
  literal extraction. Both guards now classify the complete literal through
  the real child search roles. Names/count/quiet controls remain allowed.
- The mode-2 raw recursive-search exemption now has an extraction fallback:
  recursive witnesses left outside recognized strings still deny. Ruby/Perl
  backticks and Lua equals-delimited long strings are extracted atomically;
  Bash does not mistake a heredoc header plus Lua brackets for a file redirect.
  PHP backticks retain the same shell-literal treatment and names-only control.
- Go newly allowed later `system("dotenvx","get")` launches after Perl `q=>`,
  `{q}` and `->q` identifiers. Bash still denied the launches but also newly
  denied the ordinary `my %h=(q=>1); print $h{q}` control. Both scanners now
  preserve these identifier positions instead of consuming following code as
  a quote-like operator. This is a false-allow repair and a false-denial repair,
  not a weakened existing deny expectation.
- Unterminated Perl `q`, `qq`, `qw` and `qx` constructs were allowed by both
  guards at cf6e337; 008f53c made Bash deny while Go still allowed. Go now marks
  an unterminated recognized construct indeterminate, matching Bash. Complete
  balanced quote operators and autoquoted keys remain allowed.
- The reported unknown-producer local skip is real, but the replayed commands
  already denied in both Go revisions through the final shell uncertainty
  check. It is not an observed end-to-end regression. Producer expansion now
  records `Indeterminate` immediately, like executable here-strings and heredocs;
  a focused test checks this local invariant independently of the final check.
  Known literal public producers still allow. No new deliberate Go/Bash
  divergence is intended by these repairs.
- Lua block comments were mistaken for line comments in both scanners. The
  suggested `--[[x]] os.execute("gh auth token")` already denied through raw
  string witnesses, but replacing that body with `[[grep -r TOKEN .]]`
  reproduces an allow in both guards at 008f53c. At cf6e337 Bash denied it and
  Go allowed it. Both scanners now resume at the matching long-comment close,
  including equals-delimited blocks on the same line. Incomplete blocks now
  deny rather than allow in both guards. Plain line comments, public block
  comments and literal names-only searches remain allowed.
- Perl `q # comment` followed on the next line by
  `{public}; system("dotenvx","get"); # closing hash #` changed from deny in
  both guards at cf6e337 to allow in both at 008f53c. `qq` and `qw` behave the
  same; the `qx` variant regressed in Bash, while Go retained a denial. A
  whitespace-separated hash now starts a comment, not the quote delimiter.
  Both scanners find the actual delimiter after the comment. Merely abandoning
  the operator is insufficient: a hash inside the eventual literal could then
  hide a later launch, and delayed `qx` source would lose its execution role.
  Adjacent `q#public#`, comment-delayed public literals and `qx` date controls
  still allow. No old denied expectation changes to an allow.

- The reported regex backtick examples already denied in both guards at both
  revisions through independent literal witnesses. Ruby
  `p /#{system("dotenvx","get")}/` did allow in both guards at both revisions:
  it is a confirmed pre-existing shared interpolation gap, not an 008f53c
  regression. Interpolating regex bodies now receive bounded nested scanning,
  including Perl quote-like argv inside the interpolation. A cumulative scan
  budget denies overlapping malformed slash candidates before quadratic work
  can outlive the analyzer deadline. Only regexes without
  interpolation witnesses remain opaque. A separate existing split also showed
  Bash denying inert `x = /grep -r TOKEN ./` regex data while Go allowed it at
  both revisions. Go now retains that conservative raw recursive-search witness
  even in opaque regex data, closing the observed Go-looser split without
  claiming that non-interpolating regex data executes. Public interpolated commands and
  names-only searches still allow. The required ordinary `=~ /a+/` and `=~ /x/`
  controls already allowed in Go but denied in Bash because generic attached
  option probing mistook the source suffix for a `~user` path. Bash no longer
  splits that Ruby/Perl operator, or treats interpreter brackets after a heredoc
  header as shell glob operands. Decoded literal reader arguments still receive
  the normal path and search classification. These false-denial repairs add
  must-allow cases without changing an existing denied expectation.

Permanent coverage is the 306 cases in `testdata/hook/audit25.json`, replayed by
both retained shell suites and `internal/hook/audit25_test.go`, plus lexer, argv and local
producer tests in `internal/hook/policy/audit25_test.go`. Every fixture is
synthetic. Applicable native CI and installed-host failure testing remain
separate requirements; these tests establish no host sandbox guarantee.

## Confirmation audit 25: complete Go child roles and scoped launch inputs

Q1 through Q8 repair directional parity gaps without changing existing denied
expectations. The earlier commit-review fixes above remain in place.

- Q1: interpreter fallback command witnesses enter the complete command
  dispatcher rather than a second known-program registry. Archive stdout roles,
  multicall busybox/toybox applets, gmake normalization and credential printers
  therefore share top-level behavior. Unidentified strings are positive witnesses,
  not unknown-launcher argv slots: prose such as "not env", interpolation in
  prose and Lua bracket data do not become nested commands or filesystem globs.
  Identified shell-launch APIs still receive full shell-source analysis. A
  malformed pipe literal can retain a positive child witness without treating
  arbitrary parse failures as denials. Valid fallback shell source uses the shared
  statement classifier, retaining declaration assignments, sequential cwd changes
  and pipeline producer roots rather than dispatching isolated argv calls.
  Best-effort argument scans retain completed statements before a malformed
  suffix, with prose treatment scoped to those statements rather than executable
  children. An unresolved first word stays prose instead of becoming the source
  builtin through empty-path normalization; inert quoted heredoc substitutions
  therefore retain their existing allow outcome and positive printer controls.
- Q2: retain the shared Lua long-string scanner from the commit-review repair,
  including matching equals delimiters and versioned Lua/LuaJIT. Add credential
  printer and public-reader coverage inline, in stdin and through argv. Existing
  backtick, template and Perl quote-like extraction continues to use the same
  literal and child classifiers. Single-word witnesses also reach command roles,
  including long-bracket printenv and harmless true controls. JavaScript template
  expressions are extracted with balanced strings, comments, regexes and nested
  templates, then scanned by the shared interpreter classifier under lexical work,
  depth and deadline bounds. Template literals retain positive string witnesses;
  quoted heredocs preserve escaped interpolation instead of decoding it as code.
- Q3: normalize Ruby's literal [executable, argv0] launch operand before
  classifying its remaining argv, with and without parentheses. The display
  name never replaces the actual executable. A recognized safe pair is not
  reinterpreted as an unrelated list-first launch.
- Q4: PHP proc_open literal command arrays share the existing list-first launch
  parser and child dispatcher. Output descriptors and the pipes variable are
  not command operands. Inline and valid <?php stdin bodies share classification.
- Q5: Deno.Command combines its literal executable with each literal options.args
  array. Balanced object-value scanning distinguishes top-level args from nested
  option data, accepts quoted keys and static templates, and preserves duplicate
  positive witnesses. Valid shorthand properties before or after args are skipped
  without discarding collected argv. Comments and strings containing API text
  remain inert.
- Q6: sudo consumes child NAME=VALUE operands after its options and registers
  them through shared environment checks before child dispatch. Configured
  Kubernetes/AWS filenames apply to readers and interpreter literals only within
  that invocation. Scoped environment and directory-option state cannot leak to
  a later statement. Other modeled wrappers retain these assignments when they
  dispatch sudo or env children.
- Q7: Parallel and xargs share listing-producer certification for find, fd, rg,
  ls and git. Protected or uncertain producer scopes cannot borrow a clean
  consumer cwd. Parallel option/template parsing is shared with ordinary
  dispatch; explicit input operands keep their own roles. Consumer-side scoped
  assignments participate in the proof. Recognized fd type options consume their
  value without accidentally turning it into a producer root. Public producer
  roots and metadata-only consumers remain allowed.
- Q8: command-slot analysis consumes and checks every executable option value,
  including attached/clustered values, instead of returning after a safe first
  value. Missing later values deny. The same launcher option normalizer handles
  su's command detection and strict slot classification. Safe repeated values
  and option-like data retain their existing roles. Make/gmake clusters share a
  normalizer with the database-printer check, so -sE and attached recipes retain
  their executable slot while preceding value-taking options consume their data.

Permanent coverage is `internal/hook/policy/audit25_launch_test.go`,
`internal/hook/policy/audit25_review_test.go`, option-normalizer tests and the 487
synthetic cases in `testdata/hook/audit25-launch.json`, replayed on both adapters
by `internal/hook/audit25_launch_test.go`. Candidates are analyzer/envelope data
only, with a disposable HOME. These Go checks do not establish installed-host
protection, replace provider/OS CI, or certify Bash deadline and malformed-shell
repairs (Q9 through Q11) without their subprocess checks.

Exact integration replay also retains Ruby executable/argv0 pairs, PHP proc_open
arrays and Deno.Command options.args on the Bash side. The existing bounded
interpreter literal scanner normalizes these shapes into shell-quoted argv for
full child classification. Balanced option values keep nested args keys, comments
and quoted API text inert; repeated args and shorthand properties retain positive
witnesses. Both shell suites add 28 stdin/inline deny and public-data controls from
the launch corpus. Existing broad Bash environment-name and indirect-write
policies remain unchanged; these targeted controls do not claim parity for every
safe source-language spelling.

## Confirmation audit 26: bounded Bash scans and shared Go source normalization

- R1: bound raw protected-name scans with a 200 ms subprocess alarm and the
  shared analysis deadline. Match filename word runs once, without retrying
  every suffix of long literals. Incomplete scans deny in every caller.
  Synthetic Node/Python dotted-call heredocs include ordinary public literals,
  protected names, inert writer data and injected scanner timeouts on both
  adapters. Oversized source denies within the subprocess test deadline.
- R2: normalize unquoted member-access chains before literal launch recognition
  in the shared interpreter tokenizer. Spaces, tabs and newlines around a dot
  do not hide Deno.Command or another recognized member API. Literal strings,
  regex data and unrelated Ruby/Perl statement newlines remain separate tokens.
  Numeric words stay separate so member normalization cannot reduce work counts.
  Inline source, heredocs, here-strings, producer input and argv share the rule.
- R3: split attached executable-code options into option and source before the
  shared interpreter audit. The option grammar covers Python/PyPy -c, Ruby -e,
  Perl -e/-E, JavaScript -e/-p/--eval=/--print=, Lua/LuaJIT -e, PHP -r/-B/-R/-E
  and their long forms, Rscript -e and awk/gawk -e/--source=. Recognized
  short-option clusters retain the code suffix with optional numeric Perl/Ruby
  flags, including Ruby -0/-0777 record separators. Value-taking flags consume
  their operands and stop cluster parsing, including Ruby -E encoding operands
  in attached and separate forms. Script operands and -- end option normalization;
  positional jq/yq filters retain their data roles.
  JavaScript -pe retains both code-bearing interpretations as positive witnesses
  so a source word starting with e cannot be truncated out of recognition.

Permanent coverage is `internal/hook/policy/audit26_test.go` and
`internal/hook/audit26_test.go`. Both Claude and Codex adapters replay string and
argv envelopes, env wrappers, separate/attached option forms and protected/public
launch pairs. Member-chain cases also cover all executable stdin forms. Printed
API text, comments, regexes, ordinary output and public jq/yq data remain must-allow
controls. Tests analyze candidate source only, with synthetic metadata and a fake
HOME. Bash R1 coverage is retained in `tests/test-guard.sh` and
`tests/test-codex.sh`. Existing expectations are unchanged. Synthetic checks do
not establish installed-host protection or native macOS/Windows behavior.

## Confirmation audit 27: bounded source roles, launch provenance and framing

All evidence is synthetic JSON supplied to guards, never executed candidate code.
Existing two-second Go analysis and Bash phase/overall budgets remain unchanged.
The cwd-resolution cache and BSD wc correction predate this integration and are
preserved. Applicable platform CI and installed-host failure checks remain gates.

- S0/S1: normalize qualified Deno constructors and reject missing required
  interpreter operands. Empty source, optional Perl -F and LuaJIT -O values,
  script boundaries and ordinary argv data keep their roles.
- S2/S21: validate decoded tool-name controls before extraction and unsupported
  dispatch. Genuine unsupported names still allow; malformed names deny.
- S3/S17: protect Git configuration directory equality, including linked gitdirs,
  and share XDG prefix normalization for file tools, with the HOME fallback and
  effective write-classifier overrides. This is policy parity, not host expansion.
- S4: linear CRLF normalization and alarm-bounded preprocessing share the overall
  deadline. Near-cap inert writer bodies retain their multiline allowance.
- S5/S6: literal PHP proc_open cwd (including case-insensitive function names)
  and Node/Bun cwd options anchor child argv and shell-string reads. Child state
  does not affect siblings. Public launches retain existing parent-cwd checks.
- S7/S8: file-backed xargs provenance reaches the unwrapped child. Metadata-only
  exemptions remain. Pipeline recipients replace inherited stdin provenance,
  without dropping explicit recipient redirects or uncertain producer checks.
- S9/S10: UV and systemd-run select the actual child with option arities and
  child-local directories; attached short values and UV --only-group are data.
- S11: Docker volume/mount mappings translate reader operands to protected host
  paths, including workdirs, short clusters and mount precedence. Public project
  mounts and env-file consumers still allow. Split CSV fields from brace
  expansion never become a mount source supplied in a later argv word.
- S12/S13: complete assignment nodes expose array/index substitutions. Bounded
  unquoted scalar field splitting precedes dispatch and globs. Empty IFS is
  known separately from unknown values; comments and literal IFS text are inert.
  IFS assignment proofs use the nested shell's source positions, not offsets in
  the outer quoted command argument. Child-shell IFS state and proofs do not
  escape into later parent commands. Unknown and indirect mutations still deny.
- S14/S16: validate Bash function/time framing, including the time -- terminator,
  arithmetic operand roles and parameter operators without evaluation. Nested
  expansion operands and valid standalone time remain supported. Constant
  increments deny in Go as well as Bash; protected nested children still deny.
- S15: unterminated recognized executable literals carry indeterminate status and
  remain budgeted, including Python strings. Script/data arguments keep path
  witnesses without being rejected as malformed executable source.
- S18/S19: cap decoded argv count/UTF-8 bytes before preparation and file-tool
  path/component bytes before matching. Both Go adapters match the argv caps;
  explicit shell source retains the existing multiline/heredoc allowance.
- S20 differential record: Bash now certifies bounded harmless literal nested
  eval, matching Go rather than copying a safe-command over-denial into Go.
  Protected reads, unresolved source, caller-state mutations in Bash and excessive
  depth still deny. Go may track literal cwd effects precisely; subsequent
  protected reads deny. These paired controls create no remaining divergence row.
- S22 differential record: Bash now rejects malformed patch framing, section/move
  order and mistyped workdirs. Remove the former `malformed_safe`/`oversized_safe`
  exception from the exact divergence inventory. Both Go adapters check patch
  framing and accept End of File only within a completed update hunk, retaining
  malformed, protected-target and post-marker denials.

Permanent coverage is in audit27 Go policy, paths, patch and adapter tests,
plus the audit27_ shell cases. Tests retain must-allow data arguments, optional
operands, public pipelines, empty IFS and valid EOF markers as well as denials.
The denied-corpus callback now matches the production lexical-store check before
its missing-bare-operand exception, retaining all regenerated nested-eval variants.
`audit27_s4_preanalysis_deadline` is the only new injected-dependency distinction;
it is named above and is not a Go-looser policy outcome.

## Review a3b0306: effective patch stdin and brace-cap propagation

`review_a3b0306_*` cases submit synthetic envelopes to both adapters, never run
candidate commands, and keep file contents and symlink metadata disposable.
The Go policy tracks the effective stdin source separately from interpreter-body
witnesses. Pipeline input replaces inherited stdin, explicit stdin redirects
apply in order, and non-stdin heredocs cannot certify patch framing. An effective
pipe, file redirect, descriptor duplication, here-string or absent source denies
as indeterminate. Prior same-scope stdin-heredoc denials remain conservative;
child redirects still shadow ancestor patch bodies. Valid public heredocs,
explicit fd 0, file/pipe input shadowed by a heredoc and sibling scopes retain
positive controls.

The Bash tokenizer retains input descriptor identity. Patch dispatch requires a
stdin heredoc, not an arbitrary retained body. Its single-body tokenizer denies
multiple pending heredocs rather than associating a body with the wrong source.
File inputs on other descriptors still receive protected-path checks. Both guards
deny patch streams whose framing cannot be certified, including wrapped calls.

Every Bash brace enumeration budget failure sets a denial reason. Filename
selectors already interpret failure conservatively; negative-selector checks
cannot certify exclusions on failure, and Grep propagates their budget reason.
Tokenizer callers retain the reason on failure. Best-effort argument scans retain
cap failures and fall back to a raw protected-mention check for other expansion
failures. Depth, scan-step, alternative and Cartesian-product cases deny while
shallow public command text and inert printer data retain positive controls.
The depth regression was allowed by a3b0306 but denied by 4f6a213. Synthetic
replay does not establish installed-host or cross-platform protection.

## Confirmation audit 28: launch witnesses, effective patches and bounded selectors

All cases are synthetic JSON guard submissions; candidate commands are never run.
The existing two-second Go policy deadline and Bash phase/overall budgets remain
unchanged. Neither these tests nor refreshed fixtures establish installed-host
protection or native macOS/Windows behavior.

- T0/T7: retain Deno executable/args witnesses before unsupported options, including
  spreads, computed properties, methods and incomplete trailing fields. Recognize
  PHP literal argv in both `[...]` and `array(...)`, including consecutive decimal
  integer keys and mixed explicit/implicit entries; apply existing child cwd
  checks. Dynamic values and nonconsecutive keys are not certified as literal
  argv. Public PHP controls stay allowed despite Bash's descriptor over-denial.
- T1: apply complete patch framing and protected physical-target checks after
  wrapper dispatch. Go uses child-local cwd and innermost stdin redirect scope;
  ancestor bodies shadowed by child redirects are not extra patches. Same-command
  redirects retain existing denials, wrappers retain input provenance and sibling
  scopes restore correctly. Native and valid public patch controls remain.
- T2/T3: inspect active substitutions hidden by single-quoted AST parts inside
  double-quoted parameter words and array indices. Go rejects quotes throughout
  arithmetic operands, including nested parameter defaults/replacements and
  substring offsets/lengths; substitution bodies retain their own quote context.
- T4: selector basename recursion requires progress and has a depth limit, so
  root globs cannot exhaust the Go stack. Protected re-includes still deny.
- T5/T6: Bash extracts oversized first lines linearly and bounds credential
  selector bytes, cumulative suffix work and deadline checks before costly scans.
- T8/T9: preserve safely quoted trailing operands of attached env split-string
  options and register separated/attached systemd-run configured credential
  assignments in the Go child's environment/path state, without sibling leakage.
  Bash's attached --setenv coverage is not claimed by this Go-only addition.
- T10: require children for timeout and taskset launch modes; validate taskset
  masks/lists and allowlist setsid options while retaining taskset PID queries.
- T11/T12: reject misplaced unquoted else/in calls, duplicate else branches and
  commandless coprocess redirects. Quoted/escaped words, ordinary argument
  positions and valid simple/named compound coprocesses retain their roles.
- T13: Bash validates arithmetic commands and C-style loop clauses with bounded,
  non-evaluating quote removal, normalized loop tokens and original-source
  substitution checks, including function bodies. Continued loops and quoted
  command constants/indices remain valid. Go now accepts literal double-quoted
  constants, indices and loops; its single-quote, expansion-operand and time
  framing denials remain named in the divergence table above.
- T14/T18: classify Grep on either host; default only an absent output_mode to
  files_with_matches. Explicit empty or unknown strings receive content checks.
- T15: configured credential path equality and containment fold case on every
  OS, preserving lexical boundaries and physical alias checks.
- T16: Go checks whitespace/comma selector alternatives without dropping the
  original whole-selector denial, including order-sensitive forms. Brace tokens
  retain their host semantics; safe selector unions share one bounded metadata
  walk and expansion budget. Bash whitespace-list coverage is not claimed.
- T17/T19: Bash bounds Grep glob/type bytes and components before all selector
  processing, and bounds brace depth, scan/split steps and deadline checks. Go
  mirrors the 128-separator Grep bound, rejects failed brace enumeration even in
  names-only mode and caps unquoted shell brace depth at 64. Inert quoted data
  and public shallow selectors retain their controls. Patch-only symlink
  fixtures are removed before later shell search controls to avoid altering
  their scope; no protected-read expectation is removed or weakened.

Permanent coverage is in audit28 policy, paths and adapter tests, the integration
boundary tests and audit28_ cases in both shell suites. Regeneration tests require
all 15 new Go-stricter names to be exact and directional; no class-ii difference
can use their allowlist to certify an allow. Canonical shell inventories use
Bash 4+; stock Bash 3.2 inventory checks omit only the seven named positive
controls that the suites cannot parse there. Denials and every other inventory
key remain mandatory. Synthetic inventory tests verify both runtime paths and
reject attempts to overwrite the canonical inventory from Bash 3.2.

## Review 935ad4e: Docker bind and container physical parents (merged in #17, CI green)

This closes the Go side of the recorded class (i) gap, not a Go-looser class (ii)
regression. With disposable `work/alias` pointing to `home/.aws/inner`, both guards
previously allowed these synthetic protected-reader aliases:

- `docker run -v ./alias/..:/input:ro alpine cat /input/credentials`
- `docker run --mount type=bind,src=./,dst=/input alpine cat /input/alias/../credentials`

The Go mapping now retains raw bind-source, container-operand and workdir
components until the shared metadata-only protected-path check resolves symlinks
before parent traversal. The prior lexical witness remains independent, so no
existing protected denial is weakened. Longest-target and last-same-target mount
precedence remain intact. A parent at the bind root stays in the container
namespace, not the host source's parent; nested mounts replace their outer source.
Podman uses the same Docker path roles, including container-qualified `cp` sources.

Permanent tables are `TestDockerBindPath`, `TestDockerBindPhysicalParents` and
`TestDockerPhysicalParentsBothAdapters`. They cover separate/attached/clustered
`-v`, `--volume`, `--mount` with `source=`/`src=`, absolute and relative sources,
intermediate symlinks, container workdirs, missing credential-name leaves and
container-qualified copies. Public aliases, ordinary credential basenames and
mount-boundary/precedence controls remain must-allow or unmapped controls.
Candidate commands are never executed. The retained Bash guard still allows the
two recorded aliases and is unchanged. Exact retained-suite divergence inventories
remain separate from these new Go regression tables; synthetic replay does not
establish installed-host protection or native macOS/Windows behavior.

### Audit 28 follow-up: UV tool runners and relocated gh credentials (merged in #18, CI green)

The Go-only `TestAudit28UVToolOptions` witnesses close the shared tool-runner
backlog without changing the frozen Bash executables. Synthetic examples include
`uvx --directory HOME/.aws cat credentials` and
`uv --directory HOME/.aws tool run cat credentials`. The bounded UV parser now
selects the actual executable for `uvx`, `uv tool run` and `uv run`, including
options before `tool`/`run`, attached values, `--from` and option terminators.
Source options (`--with-requirements`, `--env-file`, `--config-file`, local
packages, cache and project selectors) retain protected input witnesses. Source
paths are checked after `--directory` regardless of option order. Project,
editable and directory selectors also check the known metadata filenames for
protected aliases, without opening their contents. Unknown/incomplete launch
options deny. Public children, help/version, metadata queries and sibling cwd
controls remain allowed. `TestAudit28LaunchSystemdEnvironment` already covers
attached `--setenv` on Go; the Bash-only half remains a backlog item.

`TestAudit28RelocatedGHHosts` closes synthetic reads such as
`GH_CONFIG_DIR=custom cat custom/hosts.yml` and
`export XDG_CONFIG_HOME=custom; rg synthetic custom/gh/hosts.yml`. Both directory
variables register only their gh credential file, not every public file in the
selected directory. Inherited settings also reach native file tools, lexical
and physical path checks, case-folded aliases and bounded content searches.
Inline, exported, static-expanded and env-wrapped settings share the existing
configured-path machinery. New directory witnesses retain branch alternatives
but do not leak from child environments into sibling reads; existing provider
scope rules are unchanged. Explicit configured rg file inputs deny even with
names-only output. `TestAudit28GHConfiguredPaths` checks absent files and dangling
aliases. `TestAudit28GHConfigCertification` prevents static rg exclusions from
certifying arbitrary `GH_CONFIG_DIR` locations. The existing gh token/status
printers still deny after relocation, while ordinary status and direct approved
`secret stash` pipes retain their previous controls.

These are synthetic adapter decisions on Claude and Codex, not installed-host
or native macOS/Windows evidence. No retained shell expectation is weakened.
The existing divergence generator remains authoritative for any measured rows.

## Confirmation audit 29: bounded launch, patch and syntax witnesses

U0 recognizes static computed Deno argument keys, retaining witnesses across
surrounding spreads. U5 applies constructor cwd only to the classified child;
U6 preserves executable paths containing `@` when peeling package launchers.
Dynamic constructor options do not become static allow proofs.

U1/U4 validate effective patch stdin after bounded non-executing expansion.
Unresolved parameters, arithmetic and command substitutions deny; quoted heredoc
payloads remain literal. A separate static-parameter Git-header check retains
Bash's conservative quoted Git-write denial without expanding literal payloads.
U14 protects inherited GIT_DIR and GIT_COMMON_DIR roots lexically and physically,
including absent metadata, missing leaves, symlink aliases and tool workdirs.

U7 reparses opaque extglob patterns and denies malformed or unsupported active
substitution syntax. U10 denies escaped backquote residue that the shell parser
cannot faithfully represent. U12 conservatively tracks possible arithmetic
values independently of ordinary variable uncertainty: every loop item,
assignment, append and branch remains visible, including identifier chains and
compound declarations. Numeric/inert controls and child-state isolation remain
covered. Unsupported active reevaluation is a deliberate tightening, not shell
execution by the guard.

U18 caps raw literal extraction before path metadata work and checks the shared
deadline between bounded raw-body regex windows. Literal limits apply to decoded
interpreter source, not shell quoting fragments; the existing 256-literal
boundary remains valid for inline, heredoc, here-string, pipe and argv forms.
Template exemptions, long protected-name witnesses and inert large writer bodies
retain their roles. Go's two-second analysis budget is unchanged. The separate
two-second input-read budget is not a strict two-second end-to-end guarantee.

U9/U19 conservatively include hidden intermediate glob directories and globstar
matches, even without a local dotglob/GLOBIGNORE witness. This intentionally
closes the two default-hidden-glob U13 differences as denials rather than losing
a real protected match under child-shell options. Literal quoted globs and final
basename dotfile semantics retain their existing behavior. Literal glob ancestors
use native OS lookup instead of directory-entry regex matching: Windows 8.3 aliases
such as RUNNER~1 need not appear in a parent's long-name listing. This preserves
matches when HOME is outside cwd without changing wildcard or dotfile rules. A
synthetic alias/listing mismatch runs on every OS; it does not replace native
Windows CI or installed-host checks.

U2/U3 have the Go-side follow-up below, pending applicable CI. U8 and U11
retain named M2.1 review entries in ROADMAP.md; their remaining malformed-input
differences are not claimed fixed by these synthetic tests. Go-side U15-U17 and
timing follow-ups are described below, pending applicable CI. Installed-host
failure evidence remains a separate gate.

### M2.1 U2/U3 coprocess framing and effective patch recipients (merged in #19, CI green)

U2 rejects misplaced unquoted coprocess head words (then/elif/else/fi/do/done/
esac/in/select/!/}/]]), including redirected and pipeline heads. The parser may accept
those as ordinary calls or names even though Bash rejects their grammar.
Parser-only function/nested-coprocess heads and names before noncompound
commands also deny as uncertified. Quoted/escaped executable words, ordinary
simple calls, valid named compound bodies and nested coprocesses inside a real
body retain their roles. Candidate strings are only parser/analyzer input.

A redirected simple executable can reside in CoprocClause.Name while Stmt.Cmd
is nil. Go now reconstructs a call using that same word and the original
redirects, rather than checking only shell executable names and skipping every
other command's dispatch. Initial adjacent numeric descriptor tokens can also
be misplaced in argv; Go restores their descriptor role and checks the actual
executable, including a pipeline's leftmost call. Spaced/quoted/escaped numeric
executable names keep their original roles. In particular, coproc apply_patch with a malformed or
protected heredoc now reaches full patch validation. Coprocess stdin begins at
its own opaque pipe; an ancestor's public heredoc cannot certify it. Explicit
child heredocs may replace the pipe, and restoring the scope preserves siblings.

U3 retains the a3b0306 rejection of effective pipeline/file/descriptor/here-string
input and adds regression coverage for process substitution, wrappers, argv,
compound bodies and coprocesses. An apply_patch argv operand may select bytes
other than stdin, so even a public stdin heredoc cannot certify that invocation.
Those alternate sources deny instead of borrowing the heredoc's framing proof.
Git apply already denies mutating modes, including dashed Git dispatch; its
explicit read-only check/stat modes remain allowed for public input.

The earlier patch -o/--output exception certified only an output destination,
not original files selected by unified/context diff headers. Go now denies
patch content operations until that grammar has a bounded certifier, even when
a public output is explicit. This is a deliberate tightening of the prior
public patch-output fixture, not a claim to parse unified/context patches.
Source-free patch --help/--version/-v controls remain allowed. Valid public
apply_patch heredocs, including inherited compound-body input and recipient
heredocs shadowing a pipe, retain positive controls.

The retained Bash guard is frozen. Its single-body tokenizer and compound/
pipeline provenance limits remain; in particular the documented U3 public
ancestor-heredoc over-denial is unchanged. Go-only closure does not close the
Bash-only backlog, establish a sandbox, or supply installed-host/native CI
failure evidence. The measured supplemental fixtures are exact, directional
Go denials, with source and explicit bash -c argv forms listed separately.

Named supplemental replay entries (the argv suffix changes only the envelope).

- `m21_u2_reserved_then`, `m21_u2_reserved_then_argv`: misplaced then head.
- `m21_u2_reserved_redirect`, `m21_u2_reserved_redirect_argv`: fi with redirect.
- `m21_u2_reserved_select`, `m21_u2_reserved_select_argv`: select without a
  certifiable loop body, represented by the parser as an ordinary call.
- `m21_u2_descriptor_reserved`, `m21_u2_descriptor_reserved_argv`: an initial
  descriptor cannot hide a misplaced reserved-word executable.
- `m21_u2_function_head`, `m21_u2_function_head_argv`: parser-only function head.
- `m21_u2_named_noncompound`, `m21_u2_named_noncompound_argv`: uncertified name
  before export, rather than a real named compound command.
- `m21_u3_coproc_malformed`, `m21_u3_coproc_malformed_argv`: malformed patch
  body on a redirected simple coprocess executable. The focused Go policy tests
  also target public-link.txt, a disposable symlink to a synthetic .env file,
  to retain the physical protected-target witness without raw protected text.
- `m21_u3_coproc_descriptor`, `m21_u3_coproc_descriptor_argv`: an initial
  output descriptor cannot hide a malformed patch recipient.
- `m21_u3_coproc_descriptor_pipeline`, `m21_u3_coproc_descriptor_pipeline_argv`:
  the same restoration reaches a coprocess pipeline's leftmost patch call.
- `m21_u3_coproc_fd3`, `m21_u3_coproc_fd3_argv`: restoring the descriptor must
  not mistake fd 3's public patch heredoc for effective stdin.
- `m21_u3_coproc_protected`, `m21_u3_coproc_protected_argv`: synthetic protected
  patch target on the same previously skipped executable path.
- `m21_u3_coproc_inherited`, `m21_u3_coproc_inherited_argv`: coprocess pipe
  cannot inherit a parent's public patch-body proof.
- `m21_u3_patch_output_pipe`, `m21_u3_patch_output_pipe_argv`: opaque pipeline
  diff input despite explicit public output.
- `m21_u3_patch_output_file`, `m21_u3_patch_output_file_argv`: opaque file diff
  input despite explicit public output.
- `m21_u3_patch_output_heredoc`, `m21_u3_patch_output_heredoc_argv`: unsupported
  unified diff grammar remains uncertified even with public-looking headers.
- `m21_u3_patch_output_process`, `m21_u3_patch_output_process_argv`: process
  substitution diff input cannot certify the selected original files.
- `m21_u3_argv_shadow`, `m21_u3_argv_shadow_argv`: malformed argv patch bytes
  cannot borrow a valid stdin heredoc.
- `m21_u3_env_argv`, `m21_u3_env_argv_argv`: attached env -S already supplies
  apply_patch; a repeated apply_patch word is an alternate argv source. The
  earlier audit28 public control is intentionally tightened to deny, while the
  correctly formed env -Sapply_patch with no repeated executable stays allowed.
- `m21_u3_process_operand`, `m21_u3_process_operand_argv`: a process-substitution
  argv source cannot borrow a valid stdin heredoc.

### M2.1 U15-U17 raw paths and patch grammar (merged in #10, CI green)

U15 checks raw UTF-8 bytes before normalization or filesystem metadata: at most
4096 bytes total and 255 bytes per component. These are the retained Bash
whole-envelope and patch-header limits, not rune counts. All envelope path roles
(cwd, workdir, file_path, notebook_path and path) are checked, including fields
unused by the selected tool and names-only requests. Every Add/Update/Delete
source and Move to destination shares the same check, through native apply_patch
and shell/heredoc or explicit-shell argv routes. Native Windows separators also
split components. Dot/dotdot cleanup cannot erase an over-limit raw spelling.
These are path-role limits, not limits on arbitrary prose or patch body lines.
The prior TestAudit23PathBounds 4096-separator inputs remain unchanged but now
deny: their redundant spellings exceed 4096 raw bytes even before resolution.

U16 rejects every C0 and DEL byte in native patch headers, hunk headers and paths.
LF separates lines; it is not permitted within a path. CRLF now denies instead of
stripping CR. Tabs in prefixed body data remain data, not header indentation.
Malformed-byte and raw-limit errors use the existing fixed recovery guidance,
without repeating the path or body. Existing NUL/CR body denials remain.

U17 validates body grammar against upstream Codex
[parser.rs](https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/parser.rs)
and its delegated
[streaming_parser.rs](https://github.com/openai/codex/blob/main/codex-rs/apply-patch/src/streaming_parser.rs),
reviewed 2026-10-20. Body bytes are syntax only, never applied, opened as files,
evaluated or included in output. This is a bounded security-policy subset, not a
claim of identical acceptance of every lenient upstream input.

| Rule | Upstream comparison and Go decision |
| --- | --- |
| First Update chunk | An explicit @@ marker is optional. Accept initial +/-/space lines and unprefixed empty context, including after Move to. Later explicit chunks use @@ markers. The upstream test explicitly requires this allowance. |
| Empty chunks | Empty Update sections, move-only updates, consecutive empty @@ chunks and a final empty @@ chunk reject in both parsers. An empty context line counts as actual chunk content, not an empty hunk. |
| Add/Delete | Empty Add files and plus-prefixed Add data accept; unprefixed Add data and any Delete body reject, matching the implementation rather than only its abbreviated Lark grammar. |
| Context and anchors | Space-prefixed context, unprefixed empty context, multiple chunks and @@ with trailing spaces accept. Nonempty unprefixed prose and malformed @@ markers reject in both parsers. |
| Header indentation | Public indented section headers outside Update bodies and spaces around Begin/End markers accept. Inside an Update, an ASCII-space-prefixed public header is context, matching upstream. Protected header-looking lines retain the older conservative path-role denial because adapters and parser states can disagree whether they name a target; never erase an existing protected-header witness as whitespace normalization. |
| Literal heredoc wrappers | Accept exactly <<EOF, <<'EOF' and <<\"EOF\" with an exact EOF closing line, including one final newline. They are literal native framing, not shell source: never expand their contents. Upstream's broader closing ends_with(\"EOF\") rule is intentionally not used because a suffix such as otherEOF disagrees with a shell delimiter and cannot certify the same frame across adapters. Unknown delimiters and trailing material reject. |
| End of File | Accept a nonempty Update chunk followed by EOF, empty/whitespace-only lines after EOF and a following file section. Retain the existing single terminal EOF policy: missing chunks, duplicate EOF, new chunks or nonempty data after EOF deny. Upstream permits some ignored/restarted EOF forms, but the guard requires one unambiguous chunk terminator before it can certify that no later body is being reinterpreted as target metadata; the prior audit-27 denials remain unchanged. |
| Path whitespace | Keep rejecting empty or edge-whitespace target names rather than choosing between raw, trim and trim_end path interpretations across native and shell adapters. Raw-byte limits and control checks precede normalization and metadata work. |
| Outer framing | Preserve the existing requirement for one complete target-bearing envelope and at most one trailing newline. Upstream trims additional outer whitespace and accepts targetless patches; Go requires a classified target and exact complete framing rather than certifying ignored prefix/suffix material. Existing no-section and two-final-newline denials remain unchanged. |
| Environment ID | Upstream supports an optional environment selector. Go rejects it because the hook cannot certify a different execution environment or its filesystem anchor from the supplied cwd/workdir; treating it as inert prose could misclassify every target. |
| Controls and budgets | U15/U16 deliberately remain stricter than upstream: raw path and envelope budgets prevent unbounded metadata work, and C0/DEL header controls, including CRLF and tab indentation, deny to prevent differing decoded target spellings. Existing NUL/CR body denials remain. |

The initial required-@@ rule was an over-denial, not a security tightening.
`ordinary_patch` now allows normally and has no exception in the generator or
inventory. Protected implicit-hunk counterparts still deny through every route.
The earlier indented-safe unit control likewise retains its original allowance.
The actual `audit19_yarn_project_patch` fixture in tests/test-codex.sh contains
only Begin Patch, Update File: .yarnrc.yml and End Patch, with no chunk at all.
It is not an implicit-first-chunk example: upstream rejects that empty Update.
Keep its existing allow fixture and classify the Go denial honestly rather than
adding body data or weakening empty-update validation to make a row disappear.
A separate public project Yarn fixture with a real implicit chunk must allow.

Exact retained Codex-suite differences are named here without changing any shell
expectation or admitting a Go allow for a Bash denial:

| Case | Category | Reason |
| --- | --- | --- |
| `audit27_s22_move` | deliberate-tightening | A move-only Update section is empty; upstream rejects it too, unlike the retained Bash framing checker. |
| `audit27_s22_crlf` | deliberate-tightening | U16 rejects native patch-header CR bytes to avoid differing decoded header/path spellings instead of silently stripping them as upstream does. |
| `audit19_yarn_project_patch` | deliberate-tightening | The actual retained public project Yarn fixture is an empty Update with no body; upstream rejects empty updates too. This is not a missing-@@ or protected-name denial. |

Tests are table-driven and synthetic in internal/hook/input/m21_limits_test.go,
internal/hook/paths/limits_test.go, internal/hook/patch/m21_test.go,
internal/hook/patch/m21_upstream_test.go and internal/hook/m21_boundaries_test.go.
They include upstream compatibility controls, multibyte boundaries, every
path role, both host adapters, native and shell patch routes, and C0/DEL controls.

### Audit 29 input-read and total decision timing (merged in #10, CI green)

The two-second policy deadline starts at shell analysis, not at process launch
or the first stdin read. The existing independent two-second read deadline still
requires EOF, not merely complete JSON. Decide now also starts one four-second
timer before input reading, covering read, decode and every tool's analysis.
The timer never resets at a phase boundary. Expiry returns one fixed denial;
late workers can write only to a private buffer, never the host channel. A late
result cannot win an allow when both result and timer channels are ready.

The four-second bound excludes process startup, scheduler delays and a blocked
host-output writer. It is not a two-second end-to-end promise or evidence of
host failure blocking. An arbitrary io.Reader or blocked metadata syscall cannot
be forcibly cancelled; library callers must release blocked readers. The
single-decision CLI exits after publishing its decision. Existing five-second
host configuration and installed Bash behavior are unchanged.

internal/hook/m21_timing_test.go checks delayed first bytes, delayed complete
JSON, held-open EOF and both adapters with synthetic pipes. Scaled shared-timer
checks cover stalled reads, stalled analysis and combined phase delays, and prove
that late completion cannot append another decision. Native hosted CI and real
host failure tests remain separate gates.

## Confirmation audit 29: public Parallel pipelines (U22)

Bash recognizes Parallel `-0` and `--null` without changing the command template.
The fd producer parser consumes separate and attached `-t`/`--type` values for
file, directory and symlink filters. These filters do not certify exclusions:
the existing bounded, symlink-aware scan still checks every producer root.
A single literal read-only metadata command, such as `parallel stat`, retains
its metadata role rather than acquiring an outer `sh -c` reader role. Templates
with arguments, shell syntax or source lists still receive full shell analysis;
mutating commands do not receive the new metadata exemption.

These confirmed commands now allow in Bash, matching Go:

```sh
find public -type f -print0 | parallel -0 cat
fd --type f . public | parallel cat
find ~/.aws -type f | parallel stat
```

Here `public` contains only public files. The permanent `audit29_u22_` cases in
both host suites exercise string and explicit-shell argv envelopes, null-option
spellings, fd type-option spellings, public xargs, protected roots and symlink
aliases, additional roots, missing operands and compound metadata templates.
Protected reader and printer children still deny. Analysis budgets are unchanged.
These are synthetic decisions, not installed-host or cross-platform evidence.

The supplemental public attached-type control `fd -tf . audit29_public |
parallel cat` exposes an existing conservative Go denial, not a protected read.
Bash now allows it. Exact test keys are `audit29_u22_fd_type_attached` and
`audit29_u22_fd_type_attached_argv`. Both names are exact
`deliberate-tightening` rows; the public expectations remain unchanged.
The other supplemental differences are reviewed below.

## Reviewed bash over-denials

### Audit 29 review boundaries

U13, U20, U21 and U23 are reviewed Go-allow differences, not reasons to tighten
Go. The audit 13 directional convergence rule explicitly excludes making Go
match a provably harmless Bash over-denial. The exceptions below are limited to
the exact forms and fixture conditions stated; protected reads, credential
printers, malformed syntax and exhausted budgets are not exempted.

The divergence generator and checker admit `reviewed-bash-over-denial` only
for the four named U22 supplemental assertions below, in each host suite.
Their expected Bash decisions remain deny, and synthetic tests reject any
protected, near-name or opposite-direction exception. U13, U20, U21 and U23
remain exact documented review cases rather than unmeasured TSV rows. Bash
continues to deny those forms; this is not a blanket Go-allow exception.

### U3 public ancestor-heredoc control

The original U3 script now denies its malformed pipe-fed patches in both guards.
Its valid public control, `{ env apply_patch; } <<'PATCH'` with only a complete
Add File public.txt patch in the ancestor heredoc, still denies in Bash because
that scope cannot certify patch framing. Go preserves the actual inherited
heredoc witness and allows it. This exact public fixture is a retained Bash
over-denial after the a3b0306 stdin review, not an exception for pipeline, file,
unknown or malformed patch bytes. It is documented rather than tightening Go.

### U13: non-reader command names, default hidden globs and arithmetic counts

Exact reviewed source strings:

```sh
eval "cat\ .env"
eval 'cat\ .env'
eval \"cat\ .env\"
IFS=; c="cat .env"; $c
cat ~/*/credentials
cat ~/?aws/credentials
echo $(( $(grep -c . .env) ))
x=$(( $(grep -c . ~/.aws/credentials) ))
```

The first four forms preserve a single executable name containing a space,
not a `cat` invocation with a protected operand. The two globs use default Bash
semantics: neither dotglob nor nonempty GLOBIGNORE is active, and no selected
visible path is protected or aliases a protected file. The audit-29 U9/U19
closure now conservatively includes hidden intermediate directories even without
an explicit option witness, so these two original default-glob examples deny
in both guards. They are no longer retained Go-allow exceptions. This deliberate
Go tightening avoids losing a protected match when options or child-shell
semantics cannot be certified. Final basename dotfile semantics are unchanged.
`grep -c` does read its input, but emits only counts, consistent with the
existing top-level non-content grep exemption; calling these forms non-reading
would be inaccurate.

A safe Bash fix needs quote/splitting provenance through eval and empty IFS,
component-aware hidden-glob handling, and role-preserving arithmetic child
analysis. Removing the raw-name or unresolved-command checks would also remove
protected-read witnesses. Retain the conservative Bash result rather than
making those broad changes in this convergence patch. Ordinary `eval "cat .env"`,
default-IFS `$c` readers, dotglob-enabled protected matches and arithmetic
substitutions that print protected content are outside this review.

### U20: literal public interpreter launches

The independent confirmation narrowed the original eight-case report to these
three reproducible source strings:

```sh
python3 -c 'import subprocess; subprocess.run("git status", shell=True)'
php -r 'proc_open(["cat","README.md"],[1=>STDOUT,2=>STDERR],$pipes);'
php -r 'proc_open(array("cat","README.md"),[1=>STDOUT,2=>STDERR],$pipes);'
```

`git status` is a modeled metadata operation; each PHP literal argv launches
`cat` on the public README.md fixture. Neither launch requests protected input,
environment output or a configuration write. Bash loses the shell-string or
PHP array/descriptor roles during heuristic source scanning, whereas Go keeps
the literal launch roles. Adjusting the broad interpreter fallback or treating
PHP descriptor arrows as inert globally could discard actual execution and
write witnesses, so these precise forms retain the documented Bash over-denial.
The independently replayed Node, Deno and Python list-argv public controls
already allowed in both guards; they are not blanket interpreter exceptions.

### U21: sudo child assignments do not configure a later sibling

Exact reviewed source strings, with a public custom.cfg and README.md and no
inherited configuration selecting custom.cfg:

```sh
sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
sudo -n AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
sudo -n AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
sudo --non-interactive -- KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
sudo --non-interactive -- AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
sudo --non-interactive -- AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
sudo -u synthetic KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
sudo -u synthetic AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
sudo -u synthetic AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
command sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
command sudo -n AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
command sudo -n AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
env SYNTHETIC=yes sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
env SYNTHETIC=yes sudo -n AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
env SYNTHETIC=yes sudo -n AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
timeout 5 sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
timeout 5 sudo -n AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
timeout 5 sudo -n AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
nice -n 1 sudo -n KUBECONFIG=custom.cfg cat README.md; cat custom.cfg
nice -n 1 sudo -n AWS_CONFIG_FILE=custom.cfg cat README.md; cat custom.cfg
nice -n 1 sudo -n AWS_SHARED_CREDENTIALS_FILE=custom.cfg cat README.md; cat custom.cfg
```

Each assignment belongs to the sudo child, which reads only README.md. The
following shell sibling does not inherit it. Go restores the parent credential
context; Bash registers assignment-looking words in its enclosing analysis
context before wrapper peeling. Simply skipping that registration would lose
the protected-child checks; restoring only the variable values would leave
cached configured paths and assignment-resolution state behind. A proper Bash
fix must isolate all of that state while preserving conditional assignment
unions, so the retained deny is documented instead. Reading custom.cfg inside
the configured child, or assigning the variable persistently before the sudo
command and later reading custom.cfg, remains protected in both guards.

### U22 supplemental controls: invalid fd type and mutating metadata child

Two supplemental controls retain Bash-deny/Go-allow differences:

```sh
fd --type unknown . audit29_public | parallel cat
find ~/.aws -type f | parallel touch
```

The first is `audit29_u22_unknown_type` (and `_argv`): the invalid type value
causes fd to fail without producing protected file names. Bash does not certify
unsupported type values. This is an external tool option error, not malformed
shell or hook-envelope framing. The second is `audit29_u22_metadata_write` (and
`_argv`): touch changes timestamps but prints no credential content, consistent
with the existing metadata-child policy. Bash deliberately retains full template
analysis for mutating children because removing it generically would also need
an implicit protected Git-write target proof. These exact controls are reviewed
Bash over-denials rather than permission to tighten Go or weaken the tests.
Neither review covers credential content output or writes to Git configuration.
The exact `reviewed-bash-over-denial` keys, on both hosts, are
`audit29_u22_unknown_type`, `audit29_u22_unknown_type_argv`,
`audit29_u22_metadata_write` and `audit29_u22_metadata_write_argv`.
Integration regeneration measures 5,722 guard assertions (48 reviewed
differences), 2,653 Codex assertions (29 reviewed differences), 76 permanent
audit denials (three stricter than Bash) and 374 audit-19 outcomes. The resulting
80 exact divergence rows add only these eight reviewed Bash-over-denial rows
and four attached-fd Go-tightening rows to the prior 68. No existing expected
decision changes. The macOS guard inventory receives the same 52 new case keys;
that metadata update does not establish a macOS runtime pass.

### U23: repeated literal public Make recipes

Exact reviewed source strings, with README.md public:

```sh
make --eval 'audit:; echo public' --eval 'audit:; echo public'
make --eval 'audit:; echo public' --eval 'audit:; cat README.md'
make -E 'audit:; echo public' -sE'audit:; echo public'
make -E 'audit:; echo public' -sE'audit:; cat README.md'
make -E 'audit:; echo public' -nsE'audit:; echo public'
make -E 'audit:; echo public' -nsE'audit:; cat README.md'
gmake --eval 'audit:; echo public' --eval 'audit:; echo public'
gmake --eval 'audit:; echo public' --eval 'audit:; cat README.md'
gmake -E 'audit:; echo public' -sE'audit:; echo public'
gmake -E 'audit:; echo public' -sE'audit:; cat README.md'
gmake -E 'audit:; echo public' -nsE'audit:; echo public'
gmake -E 'audit:; echo public' -nsE'audit:; cat README.md'
```

Go checks every literal recipe occurrence. Their only recipe commands print a
public literal or read the public README.md. Bash unconditionally denies Make
eval after executable-option normalization. Removing that deny without a
bounded Make grammar could allow Make expansions, directives or later executable
options that launch a protected reader. The exception is not a general approval
of Make eval, nonliteral expansion or unrelated Makefile execution. Replacing
the second recipe with `cat .env` or `printenv TOKEN` must still deny, even when
the first recipe is public; no protected expectation is weakened here.

## M5a native Windows file/patch boundary

These are Windows-only decisions, not new Unix divergence categories. The Bash
adapter is built only on non-Windows systems. Validated native shell requests,
including harmless strings and argv, receive the fixed unsupported-shell denial
without Bash parsing. Malformed envelopes retain the shared fixed invalid-input
denial. Existing Unix corpus expectations and every divergence row are unchanged;
Unix adapter tests are platform-scoped, and a separate native replay requires
all retained shell requests to deny.

| Native decision | Classification | Evidence and reason |
| --- | --- | --- |
| String and argv shell requests | Windows-only tightening | TestWindowsShellRequestsDeny and TestWindowsShellCorpusDeny require fixed denial, including public commands. PowerShell/CMD semantics are not Bash. |
| Drive-relative/rooted paths, device namespaces, ADS, reserved device components and trimmed suffixes | Windows-only tightening | TestWindowsFileTools, TestWindowsPatchTools and TestWindowsNativeFileAmbiguity deny ambiguous targets before anchoring, stream stripping or missing-name handling. Public ADS is no longer a file-tool allow; legacy StreamBase shell-policy tests remain separate. |
| Native junction-plus-parent traversal | Protected-role preservation | TestWindowsNativeParentTraversal compares the native resolver to an actual Win32 open. File/patch decisions deny if either the legacy physical link/.. proof or native alias proof is protected; lexical Win32 cleaning cannot erase the legacy witness. Go 1.26 irregular directory-reparse metadata participates in the component walk. |
| Case, separator, reparse, 8.3 and volume/UNC aliases | Protected-role preservation | TestWindowsFileAndPatchAliases, TestWindowsShortFileAndPatchAliases and TestWindowsUNCFileAndPatchAliases pair protected targets and patch moves with public controls. Handle names and file/directory identity retain configured credentials and known home credential directories. Missing suffixes retain their existing ancestor. Dangling reparse points deny rather than borrowing an absent-name exception. |

### M5a review: local share and Git identity preservation

| Native decision | Classification | Evidence and reason |
| --- | --- | --- |
| Local UNC shares, administrative shares and substituted drives | Windows-only tightening | TestWindowsLocalUNCStoreIdentities, TestWindowsUNCProtectedRootRoles, TestWindowsUNCProtectedIdentityWitness and TestWindowsSubstProtectedAliases retain HOME credential roles and store-directory basename rules outside HOME, with public-file controls. Local share mappings require NetShareGetInfo plus matching handle file ID and volume serial; failure or ambiguity denies. |
| Repository gitdirs hidden by share/drive/junction aliases | Windows-only tightening | TestWindowsGitDirectoryIdentityAliases and TestWindowsGitIdentityAndResolutionErrors compare target ancestors with cwd/workdir .git directories and gitfile targets using eager handle identity. Missing targets retain existing ancestors; malformed, oversized, missing-target and unresolved gitfiles deny. |
| Git metadata at a share or volume root | Windows-only tightening | TestWindowsUNCGitDirectoryRoots includes the root itself in HEAD/objects/refs or HEAD/commondir detection, even without a cwd repository marker. Read and public-write controls remain allowed. |

Local-machine detection includes native computer names, loopback addresses, local
interface addresses and DNS aliases resolving to those addresses. DNS lookup is
bounded; detection/lookup errors deny rather than asserting a remote/public role.
User-supplied extended UNC and bracketed IPv6 paths retain ambiguous-path denial;
they are not newly accepted device spellings. Required C$, share, junction and
subst fixtures fail explicitly if unavailable, with exact cleanup checks for
created shares and substituted drives. These tests require windows-latest runtime
evidence; cross-compilation does not establish native alias coverage. No Unix
expectation, installed guard, plugin manifest or divergence inventory changes.

The run 40232530209 public-control corrections are over-denial repairs, not
new Unix divergence categories. TestSamePathIdentity injects Win32 invalid-name,
bad-pathname and non-directory errors on every platform: impossible operands
cannot establish identity, while access/I/O errors and bounded-proof exhaustion
remain conservative. Equal missing suffixes require identical existing ancestors;
a shared temp/volume ancestor alone is not a match. Native configured-path public
controls retain a missing custom.cfg witness without treating interpreter source
or README.md as that credential. Bash-policy argument probing retains its
pre-step-7 inert-data rules, without consulting strict native path validation or
handle identity. Strict file/patch checks keep their native validation.
The Windows shell adapter continues to deny all requests without Bash analysis.
That correction required an existing regular HEAD for Git signature discovery,
so an undeclared legacy directory did not gain a Git role solely from a metadata
error. The refs/ symbolic-link tightening below adds Git's explicit legacy HEAD
rule without restoring error-based classification. Explicit gitdirs, inherited
Git roots and alias denials remain independently protected.

### dangling symbolic HEAD Git-signature gap

Resolved as a classified cross-platform tightening in the staged Go hook only.
Git's [`setup.c` `is_git_directory` and `validate_headref`](https://github.com/git/git/blob/master/setup.c)
use lstat and accept a symbolic HEAD when readlink succeeds and its literal text
starts with `refs/`, without requiring that target to exist. Shared
`writes.go` `gitHeadSignature` applies the union of that rule and the earlier
"HEAD stats to a regular file" rule, because Git for Windows and NO_SYMLINK_HEAD
builds may follow a HEAD link rather than validate its text. So a non-refs link
to a regular file still counts, as before, while a dangling non-refs link,
lstat or readlink errors alone, and a junction HEAD to a directory do not.
Windows `nativeGitDirectory` keeps its earlier fail-closed answer when HEAD
exists but cannot be resolved (os.Stat errors other than not-exist). Existing
objects/refs or commondir requirements are unchanged. This preserves the run
40232530209 metadata-error over-classification repair, which concerned missing
HEAD resolution, and is strictly tighter than both previous rules.
Explicit gitdirs, inherited Git roots and alias denials remain independent.
The frozen Bash guard and installed manifests are unchanged.

Exact synthetic regressions:

- `TestGitHeadSignatures` covers regular and empty regular HEADs, missing and
  directory HEADs, unborn and existing refs/ links, a refs/ prefix-only link,
  dangling and existing non-refs links, ./refs/, refs-neighbor, case and backslash
  prefixes, and a symlink loop (fail-closed in native discovery). Each runs with objects/refs and commondir layouts
  and checks config and missing hooks/new writes.
- `TestGitHeadSignatureMetadataErrors` injects missing, permission and invalid
  errors at lstat/readlink, including partial refs/ text returned with an error.
- `TestWindowsGitHeadSignatures` repeats the table through native Git-directory
  discovery, ancestor-role checks and file-tool classification.
  `TestWindowsGitHeadJunctionControl` keeps a junction HEAD public, and
  `TestWindowsGitHeadUnresolvableLink` requires native fail-closed discovery for
  an existing HEAD link Windows cannot resolve (relative forward-slash text). The
  shared table uses native separators for non-refs link text on Windows. Windows
  fixtures use CreateSymbolicLink directly to preserve literal refs/ link text;
  Go's os.Symlink otherwise rewrites it to backslashes. These Windows tests need
  native hosted execution; cross-compilation is not runtime evidence.
- `TestAudit29InheritedGitWriteRoots` now requires denial for the undeclared
  unborn refs/ layout through both shared write checks and patch dispatch. Its
  undeclared non-refs dangling layout and alias remain public; inherited-root
  subtests use that layout so their denials still prove inherited-root handling.

Fresh default-binary inventory verification retains all 5738 guard and 2669 Codex
assertions with 51 and 35 reviewed differences respectively. Regeneration leaves
all 165 exact divergence rows unchanged; this synthetic layout adds no retained
shell-suite divergence row.

### M5a review: separate Bash policy from native file semantics

Run 40236374785 at 9a35a4a still denied public interpreter source, UV URLs and
Docker arguments, and lost an inherited Git-root witness. The root cause was
native validation, handle identity and lexical traversal in shared path helpers,
not a missing Bash exception. The Windows hook already denies every shell request
before analysis. The plan's native path rules apply to file/patch tools only.

Restore Bash-reachable behavior to the passing b8399a1 implementation: Resolve
preserves raw operands, physicalWith walks components before Windows alias
canonicalization, configured credentials compare case-folded paths rather than
handle identity, and ConfigWriteProtected retains legacy Git discovery. Zero-value
Metadata follows the same rules. No audit expectation or inert-data exemption is
changed to accommodate native file semantics.

FileResolve, FileProtected, FileConfigWriteProtected and the File* search helpers
select native normalization, validation and handle identity. Only FileProtected
constructs native-mode Metadata; Bash metadata remains zero-value. ToolGlob and
ToolGrep use file APIs; filteredScopeWith selects them only for an explicit native
file-tool scan. Scope and FilteredScopeConfigured keep the Bash mode. Native home
and Git discovery stay at the file/patch boundary. All local UNC/admin-share,
subst, junction, gitdir-share and portable identity regressions are retained.

The audit-cases6-9 Windows skip list and its classification are removed. Restoring
the legacy component walker restores the .aws/credentials physical witness behind
awsx/../credentials, so TestGuardDeniedCorpus again requires every variant to deny
without an exception. TestWindowsLexicalTraversalShellVariantsDeny separately
retains both hosts' fixed all-shell denial for all eight commands.
TestWindowsNativeParentTraversal retains the public native Win32-open result as a
resolver witness while requiring file-tool denial from the legacy physical proof;
TestWindowsPolicyAndFileToolIdentityModes pairs inert Bash data
with strict native targets and a configured hardlink identity.
TestWindowsFileSearchIdentityMode retains that identity for native Glob/Grep
content/count requests while Bash filtered scope keeps its legacy behavior and
native names-only/public-file controls remain available. Native runtime
confirmation remains required; cross-compilation is not a host-protection claim.

Aliased known home credential-directory roots also deny explicit Glob/Grep
requests rather than certifying their descendants from a public share/drive name.
Public UNC roots/files remain controls; names-only behavior on Unix is unchanged.

The 4c7fbbf native follow-up keeps every file-tool path proof as the union of the
legacy proof and native identity, including configured paths and tree roots.
Go 1.26 reports junctions as irregular directory reparse points rather than
ModeSymlink; the component walker now sends those through Readlink under the
existing hop/error bounds. Unsupported directory reparses still deny. Git native
identity assertions call FileConfigWriteProtected, not the deliberately separate
Bash-policy ConfigWriteProtected helper.

TestWindowsGrepNamesOnlyCredentialRoles retains names-only Grep on an explicitly
named .aws directory even when an ancestor has a different physical/8.3 spelling.
Native directory-role checks compare the retained basename role after resolution
or identity, not the entire raw path. Opaque shares, drives, junctions and directory
symlinks remain denied. Grep applies native identity inside its existing names-only
file-symlink exception, not as an unconditional hook precheck. Existing file aliases
can return names only; content/count, explicit credential files, configured
identities and dangling aliases remain denied. The existing audit 28 and audit
envelope expectations are unchanged, and native Windows CI is still required.

FileProtected is the strict file-tool boundary. Protected and StreamBase remain
shared shell-policy helpers, where an invalid Windows filename can be inert
command data. No native file or patch target receives that exemption. Home
lookup uses explicit HOME or native USERPROFILE, and native file tools cannot
proceed with an unavailable or ambiguous home. Metadata handles request attributes
only; no credential contents are opened, echoed or evaluated by these checks.

The development-only guard-go.cmd calls only its sibling secret.exe. Missing
binary and output-failure tests are synthetic and cmd-native. The shim is absent
from installed manifests; windows-latest runtime evidence and the complete step-8
PowerShell/CMD matrix remain required. Local cross-checks do not certify native
aliases or fail-closed host behavior. Host-skipped hooks remain outside coverage.
