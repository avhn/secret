# Hook tightening decisions for M2

The default Go build now analyzes Bash tool calls through the bounded AST policy. The installed hook is still `hooks/guard-secrets`; no plugin manifest or `hooks.json` has changed. Passing synthetic tests does not establish a host shell-dialect or failure-blocking contract.

## Reviewed differences

Every row in `testdata/inventory/go-hook-divergence.tsv` must match a named case below. `deliberate-find-shim` describes an injected dependency failure that Go does not execute, not a real permission bypass. `deliberate-tightening` covers the owner-approved indeterminate-input policy and the additional audited input/output gaps. No pending-M2 categories remain.

| Case | Bash decision | Go decision | Reason |
| --- | --- | --- | --- |
| Nonempty malformed JSON (`malformed_json`, `malformed_sensitive`) | No decision | Deny with fixed complexity reason | An undecodable supported call cannot establish safe roles. |
| Malformed safe Codex patches (`malformed_safe`, `oversized_safe`) | No decision | Deny with fixed complexity reason | An absent framing pair, ambiguous header, or patch over the 40 KiB limit cannot certify safe target paths. Recognized protected headers still deny even without framing. |
| Duplicate keys, trailing JSON, wrong field types, NUL, relative envelope cwd, or envelopes above 64 KiB | May coerce or continue for some inputs | Deny with fixed complexity reason | Require one unambiguous bounded host envelope and an absolute cwd to anchor cwd-relative workdir. Non-NUL shell controls retain the Bash inert-command exception; path controls remain invalid. |
| Unresolved operands (`unresolved_file_safe`, `unresolved_positional_safe`, `unresolved_listing_safe`, `unresolved_wc_safe`, `unresolved_redirect_safe`, `unresolved_xargs_safe`, `unresolved_literal_safe`, `unresolved_no_eval`) | No decision without a protected witness | Deny as indeterminate content-producing input | Unknown parameter or substitution output cannot certify a non-protected input. Never execute the substitution to decide. |
| Unknown executable (`active_safe_command`) | No decision without a protected witness | Deny with fixed complexity reason | `$c package.json` does not establish the executable or its input/output roles. |
| Unknown wrapper option arity (`unknown_timeout_safe`, `unknown_nice_safe`, `unknown_stdbuf_safe`, `unknown_caffeinate_safe`, `unknown_xargs_safe`, `unknown_exec_safe`, `sudo_unknown_safe`) | No decision without a protected witness | Deny with fixed complexity reason | Unsupported options cannot certify which remaining words form a child command. A missing sudo option value with no child still matches Bash's no-decision behavior. |
| External find fault injection (`grep_find_exit`, `grep_find_exit_count`, `rg_find_exit`, `grep_timeout`, `grep_timeout_count`, `rg_timeout`, `git_grep_timeout`) | Deny when the injected find exits or times out | No decision on the clean synthetic tree | Go never executes find. Its own walk errors, permissions, loops, budgets and deadlines deny under dedicated fault-injection tests. |
| Ripgrep names mode with a preprocessor (`audit-cases5-6`) | No decision | Deny | `--pre cat` invokes a content-producing child and cannot be certified by the names-only shortcut. |
| Clustered xargs argv input (`audit-cases6-7`) | No decision in argv form | Deny | `-0a` consumes a protected argument-list file before invoking its child. |
| Physical protected Grep input (`audit-cases7-2`) | No decision in names-only mode | Deny | Following a symlinked ancestor before `..` reaches an actual credential file. The ordinary final-symlink alias exception does not certify this protected file input. |
| Indeterminate arithmetic content (`audit-arithmetic-unknown`) | No decision | Deny | `(( $(cat file) ))` contains a content-producing substitution and cannot be certified from arithmetic syntax. |

The audit fixtures are synthetic and permanent in `testdata/hook/audit-cases.json`. The installed Bash guard now agrees with Go on brace Grep selectors (`audit-cases2-4`, `audit-cases2-5`), clustered grep/sed options (`audit-cases4-43`, `audit-cases4-44`), Git grep pager options (`audit-cases5-1`, `audit-cases5-2`), and cd options (`audit-cases6-8`). All 76 audit envelopes deny in the default Go JSON path. Other reviewed differences remain measured in the divergence inventory.

## Parity closure and hardening

The starting trial had 24 Claude false denies and one Codex false deny. The following were restored to exact Bash parity:

- Filtered transports: `secret_run`, `header_transport`, `shell_filtered_header`. Credential expansion is exempt only in the scoped curl-header transport; ordinary printers and nested protected readers still deny.
- Scoped missing bare inputs: `no_file`, `env_chdir_empty`, Codex `cwd_safe`. Bare shell operands use metadata existence, while slash-qualified names, aliases, unresolved inputs and file tools retain protection.
- Literal/control-flow cases: `safe_loop`, `deep_safe`, `ansi_escapes_analysed`, `ansi_literal_substitution`, `ansi_nested_literal`, `control_safe`, `brace_escaped`, `ifs_brace_prose`.
- The remaining original differences are the two malformed-envelope cases, eight unresolved-input cases and `active_safe_command`, all listed above. Audited wrapper hardening adds seven documented unsupported-option tightenings.

Additional audit fixes cover config reassignment, wrapper option arity and clusters, time/coproc/let/arithmetic/C-style-for traversal, substitutions in declarations and case patterns, scoped cd propagation, both sides of printer-to-stash pipelines, quoted/combined printer flags, physical symlink/parent traversal, Grep selectors and tar mode detection. The audit reproductions run through both supported JSON adapters where applicable; Bash audit commands also enter variant testing.

`tests/gen-hook-variants.py` extracts all 777 Bash-deny assertions, including direct JSON assertions, from an unchanged disposable copy of the guard suite, and adds 56 string-command audit cases. The generated corpus includes synthetic metadata snapshots, symlinks and exact config bytes. The final local run checked 11,949 variants with zero allows; deterministic regeneration was verified byte-for-byte. Variants quote literal words with single, double and ANSI quotes, escape protected-name characters, add empty brace alternatives, and prefix executable calls with command or applicable builtin. Active expansions are not quoted into inert strings, heredoc delimiters are not quoted to disable substitution, and invalid arithmetic rewrites are excluded. Seven Bash-only injected dependency-failure cases remain recorded but skip command-text variants; Go scanner fault injection tests their actual boundary instead.

## Measurement and regeneration

Before: default shell deferral, with a separate tagged prototype.
After: one default AST path, 64 KiB envelopes and 40 KiB recursive fragments. Word, brace, recursion, glob and scan limits remain bounded. No shell interpreter or provider value API participates in decisions.

| Stage | Claude real false allows | Claude false denies | Codex false allows / false denies |
| --- | ---: | ---: | ---: |
| Starting trial | 0 (7 find shims separate) | 24 | 0 / 1 |
| Grep/split option parsing | 0 | 24 | 0 / 1 |
| Original parity closure after regression fixes | 0 | 11 | 0 / 0 |
| Audit, wrapper and variant hardening | 0 | 18 reviewed | 0 / 0 |

The current exact suite has 1382 matching and 25 reviewed divergent Claude assertions, plus 42 matching Codex assertions and 2 reviewed malformed-patch tightenings across 44 cases. The audit corpus now adds 4 reviewed stricter differences across 76 denied envelopes. Before these added regressions, the measured default p99 was 4.996 ms across 1379 Claude decisions and 4.877 ms across 31 Codex decisions. The timing wrapper measures process launch plus decision, not an installed host callback.

Regenerate with `python3 -I tests/gen-go-hook-divergence.py ABSOLUTE_BINARY`. It runs the unchanged shell suites and both implementations on the audit fixtures, refuses unreviewed suite categories or missing tightening-table entries, and writes the exact inventory mechanically. `tests/trial-go-hook.py` now builds a disposable default binary and prints grouped counts and p99; no build tag is needed. Run `bash tests/go-hook.sh guard ABSOLUTE_BINARY claude` and the corresponding Codex command for exact inventory checks.

M2 remains ready for independent review, not a completed host cutover. Real-host failure tests, dialect evidence and the supported-platform CI matrix remain separate gates.
