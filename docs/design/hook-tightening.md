# Hook tightening decisions for M2

The default Go build now analyzes Bash tool calls through the bounded AST policy. The installed hook is still `hooks/guard-secrets`; no plugin manifest or `hooks.json` has changed. Passing synthetic tests does not establish a host shell-dialect or failure-blocking contract.

## Reviewed differences

Every row in `testdata/inventory/go-hook-divergence.tsv` must match a named case below. `deliberate-find-shim` describes an injected dependency failure that Go does not execute, not a real permission bypass. `deliberate-tightening` covers the owner-approved indeterminate-input policy and the additional audited input/output gaps. No pending-M2 categories remained in the first-audit baseline; second-audit suite reconciliation is recorded below.

| Case | Bash decision | Go decision | Reason |
| --- | --- | --- | --- |
| Nonempty malformed JSON (`malformed_json`, `malformed_sensitive`) | No decision | Deny with fixed complexity reason | An undecodable supported call cannot establish safe roles. |
| Malformed safe Codex patches (`malformed_safe`, `oversized_safe`) | No decision | Deny with fixed complexity reason | An absent framing pair, ambiguous header, or patch over the 40 KiB limit cannot certify safe target paths. Recognized protected headers still deny even without framing. |
| Duplicate keys, trailing JSON, wrong field types, NUL, relative envelope cwd, or envelopes above 64 KiB | May coerce or continue for some inputs | Deny with fixed complexity reason | Require one unambiguous bounded host envelope and an absolute cwd to anchor cwd-relative workdir. Shell control bytes now deny under audit policy 1, including inert commands; path controls remain invalid. |
| Unresolved operands (`unresolved_file_safe`, `unresolved_positional_safe`, `unresolved_listing_safe`, `unresolved_wc_safe`, `unresolved_redirect_safe`, `unresolved_xargs_safe`, `unresolved_literal_safe`, `unresolved_no_eval`) | No decision without a protected witness | Deny as indeterminate content-producing input | Unknown parameter or substitution output cannot certify a non-protected input. Never execute the substitution to decide. |
| Unknown executable (`active_safe_command`) | No decision without a protected witness | Deny with fixed complexity reason | `$c package.json` does not establish the executable or its input/output roles. |
| Unknown wrapper option arity (`unknown_timeout_safe`, `unknown_nice_safe`, `unknown_stdbuf_safe`, `unknown_caffeinate_safe`, `unknown_xargs_safe`, `unknown_exec_safe`, `sudo_unknown_safe`) | No decision without a protected witness | Deny with fixed complexity reason | Unsupported options cannot certify which remaining words form a child command. A missing sudo option value with no child still matches Bash's no-decision behavior. |
| External find fault injection (`grep_find_exit`, `grep_find_exit_count`, `rg_find_exit`, `grep_timeout`, `grep_timeout_count`, `rg_timeout`, `git_grep_timeout`) | Deny when the injected find exits or times out | No decision on the clean synthetic tree | Go never executes find. Its own walk errors, permissions, loops, budgets and deadlines deny under dedicated fault-injection tests. |
| Ripgrep names mode with a preprocessor (`audit-cases5-6`) | No decision | Deny | `--pre cat` invokes a content-producing child and cannot be certified by the names-only shortcut. |
| Clustered xargs argv input (`audit-cases6-7`) | No decision in argv form | Deny | `-0a` consumes a protected argument-list file before invoking its child. |
| Physical protected Grep input (`audit-cases7-2`) | No decision in names-only mode | Deny | Following a symlinked ancestor before `..` reaches an actual credential file. The ordinary final-symlink alias exception does not certify this protected file input. |
| Indeterminate arithmetic content (`audit-arithmetic-unknown`) | No decision | Deny | `(( $(cat file) ))` contains a content-producing substitution and cannot be certified from arithmetic syntax. |
| Control-byte commands (`control_safe`, audit2 `G4`, `S18`) | Previously allowed inert text and some printers; policy 1 now requires denial | Deny with fixed complexity reason | Every command-source byte below 0x20 except LF and TAB, and DEL, denies. The same check applies to argv entries. Escaped literals remain analyzed as shell syntax. |
| Historical content with no certifiable repository (`ordinary_command#9`, audit2 `S7-11`) | May allow without a work-tree witness | Deny | Policy 2 requires a bounded repository-root scan for content-producing history. Go also denies when no repository root can be established, rather than treating an unknown history scope as clean. |
| Branch-dependent cwd (`G2`, `S9`, `G16`) | May retain the last syntactic cd target | Deny later relative reads when possible directories differ | A loop can execute zero times and a function can remain uncalled. Joining differing directory states as unknown prevents a clean branch from erasing a protected alternative. Substitution wrappers never discard that uncertainty. |
| Shell hook code and split-string escapes (`S13`) | Keyword/path checks may certify additional literal values | Analyze nested shell code, or deny indeterminate code | Go checks BASH_ENV and ENV as file inputs, other hook variables and Git execution config as bounded shell fragments, and decodes env split-string separators before analysis. |
| Archive and find input scopes (`S10`, `S15`) | Scope certifiability can differ on incomplete trees | Deny incomplete or protected scans | Creation and find reader children inspect bounded metadata including ignored directories and symlinks. No simulated copy, link or extraction state is introduced. |
| Shell patch heredocs (`patch_heredoc_prose`, audit2 `S18`) | Historical Codex suite expects allow | Deny protected or malformed patches | Policy 14 treats apply_patch heredocs as patches, not inert prose. Safe, framed heredocs remain allowed. |
| Unknown search option arity (`S8`, policy 9) | May accept additional names-only forms | Deny unknown or ambiguous options before a names-only shortcut | Supported unique long-option prefixes resolve before role classification. Names-only mode cannot hide an unknown content-producing or pager option. |
| Bounded single-element braces (`B6`, policy 13) | Glob nesting certification may differ | Deny selectors above 16 expansion levels or 64 alternatives | Globset single-element alternatives now expand, so a separate recursion bound prevents nested single-element braces from evading the alternative-count budget. |
| Interpreter environment witnesses (`G5`, `S12`) | Spelling recognition may be narrower | Deny recognized environment access in interpreter arguments | Preserve existing conservative argument checks while covering environ imports, bracketed process access, nodejs, PHP, awk, Perl Env and yq strenv. No interpreter executes during analysis. |


The audit fixtures are synthetic and permanent in `testdata/hook/audit-cases.json`. The installed Bash guard now agrees with Go on brace Grep selectors (`audit-cases2-4`, `audit-cases2-5`), clustered grep/sed options (`audit-cases4-43`, `audit-cases4-44`), Git grep pager options (`audit-cases5-1`, `audit-cases5-2`), and cd options (`audit-cases6-8`). All 76 audit envelopes deny in the default Go JSON path. Other reviewed differences remain measured in the divergence inventory.

## Parity closure and hardening

The starting trial had 24 Claude false denies and one Codex false deny. The following were restored to exact Bash parity:

- Filtered transports: `secret_run`, `header_transport`, `shell_filtered_header`. Credential expansion is exempt only in the scoped curl-header transport; ordinary printers and nested protected readers still deny.
- Scoped missing bare inputs: `no_file`, `env_chdir_empty`, Codex `cwd_safe`. Bare shell operands use metadata existence, while slash-qualified names, aliases, unresolved inputs and file tools retain protection.
- Literal/control-flow cases: `safe_loop`, `deep_safe`, `ansi_escapes_analysed`, `ansi_literal_substitution`, `ansi_nested_literal`, `brace_escaped`, `ifs_brace_prose`.
- The remaining original differences are the two malformed-envelope cases, eight unresolved-input cases and `active_safe_command`, all listed above. Audited wrapper hardening adds seven documented unsupported-option tightenings.

Additional audit fixes cover config reassignment, wrapper option arity and clusters, time/coproc/let/arithmetic/C-style-for traversal, substitutions in declarations and case patterns, scoped cd propagation, both sides of printer-to-stash pipelines, quoted/combined printer flags, physical symlink/parent traversal, Grep selectors and tar mode detection. The audit reproductions run through both supported JSON adapters where applicable; Bash audit commands also enter variant testing.

`tests/gen-hook-variants.py` extracts all 777 Bash-deny assertions, including direct JSON assertions, from an unchanged disposable copy of the guard suite, and adds 56 string-command audit cases. The generated corpus includes synthetic metadata snapshots, symlinks and exact config bytes. The final local run checked 11,949 variants with zero allows; deterministic regeneration was verified byte-for-byte. Variants quote literal words with single, double and ANSI quotes, escape protected-name characters, add empty brace alternatives, and prefix executable calls with command or applicable builtin. Active expansions are not quoted into inert strings, heredoc delimiters are not quoted to disable substitution, and invalid arithmetic rewrites are excluded. Seven Bash-only injected dependency-failure cases remain recorded but skip command-text variants; Go scanner fault injection tests their actual boundary instead.

## Second audit: 44eca2f

The binding policy covers G1-G6, G16, S7-S15, S17-S18 and B6. B1-B5 and B7 remain denied. `internal/hook/testdata/audit2.json` retains 102 cases: 93 required denials and nine explicit safe or out-of-scope allows. `internal/hook/audit_test.go` builds the audit2 layout and two disposable Git repositories with synthetic commits; it skips these history tests only when Git is unavailable. No analyzer path executes Git or reads object contents. The second corpus contributes 1,259 denied-command variants through the existing syntactic generator, in addition to the prior 11,949 variants.

The nine allows make the policy boundaries testable: deleted-only history without an explicit protected pathspec, a safe history pathspec, two general argv-variable echoes, three copy/link laundering commands, and Python/Vim script reads through an innocently named symlink. Explicit protected historical pathspecs and REV:path operands still deny even when absent from the work tree. These are policy 2, 10, 11 and 15 exclusions, not repaired leak claims. The other agent owns the corresponding SECURITY.md disclosure.

New checks cover cwd joins, unknown CDPATH and shell hook values, dotenv option failures and child analysis, history scope, archive creation and member names, interpreter environment spellings, jq option arity and shell-expanded filters, Grep globset single-element braces, control bytes, and indented or heredoc patch headers. Malformed embedded CR/NUL now takes precedence over path checks in the patch parser, keeping the denial reason stable on Windows; the existing Unix-cwd Windows test skip is unchanged.

The supplied audit2 `cmp.sh` was rerun against a complete disposable fixture, because its original `w/r2` was absent. It matched all 102 permanent expectations: 93 Go denials and nine policy/safe allows. This is decision evidence, not host-installation or runtime containment evidence.

Current verification: gofmt, go vet, go test ./..., internal race tests, GOOS=windows go vet and a 60-second FuzzAnalyze run pass. The latest recorded fuzz run completed 361,947 executions. Codex exact checking now reports 45 matches and two reviewed divergences across 47 assertions. Guard exact checking and regeneration remain blocked by concurrent inventory additions (the latest generator attempt reports `invalid result: guard/audit_compound_cd`) and by `audit_script_or_archive#6` and `audit_script_or_archive#7`: the concurrent Bash suite requires denial for the two script-symlink cases excluded by policy 11. The generator refuses those differences rather than silently rewriting them, so the divergence TSV is unchanged by this work. A process-launch-inclusive run measured Claude p99 5.245 ms over 1,464 decisions and Codex p99 4.092 ms over 37 decisions; the Claude timing run also reported inventory mismatch during concurrent regeneration. Repeat exact suites, regeneration and timing after both agents reconcile the policy-11 expectations.

## Measurement and regeneration

Before: default shell deferral, with a separate tagged prototype.
After: one default AST path, 64 KiB envelopes and 40 KiB recursive fragments. Word, brace, recursion, glob and scan limits remain bounded. No shell interpreter or provider value API participates in decisions.

| Stage | Claude real false allows | Claude false denies | Codex false allows / false denies |
| --- | ---: | ---: | ---: |
| Starting trial | 0 (7 find shims separate) | 24 | 0 / 1 |
| Grep/split option parsing | 0 | 24 | 0 / 1 |
| Original parity closure after regression fixes | 0 | 11 | 0 / 0 |
| Audit, wrapper and variant hardening | 0 | 18 reviewed | 0 / 0 |

The pre-second-audit exact suite had 1382 matching and 25 reviewed divergent Claude assertions, plus 42 matching Codex assertions and 2 reviewed malformed-patch tightenings across 44 cases. The audit corpus now adds 4 reviewed stricter differences across 76 denied envelopes. Before these added regressions, the measured default p99 was 4.996 ms across 1379 Claude decisions and 4.877 ms across 31 Codex decisions. The timing wrapper measures process launch plus decision, not an installed host callback.

Regenerate with `python3 -I tests/gen-go-hook-divergence.py ABSOLUTE_BINARY`. It runs the unchanged shell suites and both implementations on the audit fixtures, refuses unreviewed suite categories or missing tightening-table entries, and writes the exact inventory mechanically. `tests/trial-go-hook.py` now builds a disposable default binary and prints grouped counts and p99; no build tag is needed. Run `bash tests/go-hook.sh guard ABSOLUTE_BINARY claude` and the corresponding Codex command for exact inventory checks.

M2 remains ready for independent review, not a completed host cutover. Real-host failure tests, dialect evidence and the supported-platform CI matrix remain separate gates.
