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

## Third audit: policy v2 at 5ae2411

Policy v2 supersedes the earlier work-tree-history and safe-pathspec decisions. Both guards, the shell suites and the divergence inventories are reconciled here. Verification recorded in the preceding section is the historical second-audit snapshot.

### Decision boundaries

- P0: the outer `Decide` boundary recovers panics from input decoding or analysis and emits a fixed denial without the panic payload. Output errors still propagate. An unwritable host channel cannot be made to deliver a denial, so this is not a claim about host failure blocking.
- P1: Git has one dispatch path with exact global option arities and per-subcommand safe-option tables. Unknown global options deny. Unknown subcommands or subcommand options are content-producing. Repository locations resolve from `-C`, `--git-dir`, `--work-tree`, `GIT_DIR`, `GIT_WORK_TREE`, gitfiles and bare repositories, using native filesystem paths. Discovery follows the physical cwd and stops after 128 ancestors.
- Content-producing Git checks the resolved index, not the work tree. The reader accepts index versions 2, 3 and 4, including extended flags and v4 prefix-compressed names, with a 16 MiB byte cap, 100,000-entry cap, 4,096-byte name cap and checksum validation. It parses names without dereferencing object IDs or reading blobs. A bounded regular Git config file is inspected only to classify a referenced repository alias. Malformed, inaccessible, oversized, split, sparse and unsupported-format indexes deny; unknown mandatory extensions deny. SHA-256 index layouts currently fail closed. A missing index is accepted only with an initialized repository HEAD marker.
- The three P1 content-denial predicates are applied conservatively: a protected index entry, protected path argument or indeterminate repository denies. A safe pathspec does not override a protected index, including without `--full-diff`. This deliberately changes audit2 `S7-10` and the earlier safe-pathspec unit test from allow to deny. Ignored, untracked `.env` files no longer block `git log -p`. Deleted-only history remains the documented gap.
- Git execution config keys are case-insensitive; inline config, numbered config environment entries, named command environment variables and command-running options enter bounded shell analysis. Plain aliases expand into Git argv before classification. Protected executable paths also count as file inputs. Repository aliases are read from at most 64 KiB of regular local config metadata without executing Git; shell aliases are analyzed as commands. Config includes, hooks directories, executable-directory overrides, unknown config-env values, unmodeled inherited config injection and ambiguous reassigned environment provenance deny. Config getters accept a fixed set of non-credential keys; whole-config listing denies because absent credentials cannot be certified without reading config. A literal safe command or alias is not denied merely for being command-bearing. The direct `git credential fill | secret stash` transport remains allowed.
- P2: find children are fully analyzed after wrapper handling. Only the policy's metadata-child list exempts them from bounded scope inspection. Unknown children, including `echo`, count as readers. Symlinks make a scope protected or indeterminate. xargs and parallel readers inspect the cwd scope when operand names cannot be certified. An explicitly supplied, non-protected xargs argument-list file is modeled as a safe operand source; stdin-fed readers still inspect the cwd scope. Unsupported parallel option/input-list grammar denies rather than being guessed.
- P3: archives use option/mode tables. GNU tar long options resolve by unique prefix before classification. Stdout and extraction-to-command forms always deny, even with apparently safe members. Creation inspects bounded input scopes, including symlinks; unmodeled options, file lists and extraction-member globs deny. Safe literal compression/checkpoint commands are analyzed as shell text, not denied solely for invoking a command. Listing remains allowed, including protected-looking member names. cpio and 7z currently model listing only; other forms fail closed. BusyBox archive children use the same dispatch.
- P4/P5: directory-stack commands, special tilde directories, CDPATH, directory-changing shopt settings and ambiguous cd operands invalidate later relative reads. Dynamic `/proc` paths and descriptor-directory aliases deny, with only the specified harmless proc files allowed.
- P6: jq treats `-f` as a flag and selects the first positional program file after clustered/intervening options. sed inline file/execution commands, alternate addresses, option clusters and substitutions, and awk literal file/system operands resolve aliases through shared path checks. Sed script files are inspected only through a non-protected alias, as bounded regular files of at most 8 KiB; missing, non-regular, unreadable or oversized scripts deny. Awk script files remain indeterminate, and sed pattern-space execution also denies. Computed script literals and eval remain outside the guaranteed model.

### Permanent synthetic evidence

`internal/hook/policy/testdata/audit3.json` retains 386 commands from the third audit's Git, archive, directory, find/xargs/parallel, jq and script tables. Fixtures contain only fabricated files, symlinks and generated indexes. Each command runs through shell and argv analysis: 370 required denials and 16 explicit metadata, safe-command or out-of-scope allows. The allows include a cd confined to the other side of a pipe, eval and concatenated script literals, and archive listings; none is an open GO/BOTH finding. Separate tables cover safe Git forms in protected-index repositories, ignored/untracked `.env`, index versions and failures, repository/env resolution, command surfaces, metadata children, harmless proc exceptions and panic recovery in both host adapters. No analyzer executes Git or a child command.

The original 11,949 denied variants still produce zero allows. The existing audit2 corpus now has 94 denials and eight allows because P1 supersedes its safe-history-pathspec exemption.

### New measured shell-suite differences

These are differences against suite assertions, not permission to change the binding policy. The exact checker now passes after reconciling the suites and inventories.

| Case | Suite assertion | Go decision | Policy reason |
| --- | --- | --- | --- |
| `audit_history_safe` | Deny | Deny | P1: a safe pathspec does not override a protected index. |
| `git_grep_chdir`, `git_grep_clean`, `git_grep_multiple_chdir`, `git_grep_names`, `git_grep_names_long`, `git_grep_pruned_.git`, `git_grep_pruned_node_modules` | Allow | Deny | P1: grep is content-producing, and these metadata-only fixtures do not establish a safe repository index. Pruned work-tree scans no longer certify Git. |
| `git_scope_names_--cached`, `git_scope_names_--no-index`, `git_scope_names_--untracked` | Allow | Deny | P1: names-only grep flags do not supply a safe-form exemption. |
| `operand_allow#33`, `ordinary_command#8` | Allow | Deny | P1: verbose status and ordinary diff are content-producing in an indeterminate repository. |
| `find_names_only#4` | Allow | Deny | P2: echo is not in the metadata-only child list. |
| `xargs_R_safe`, `xargs_S_safe`, `xargs_arg_file_safe`, `xargs_arg_file_template`, `xargs_optional_safe`, `xargs_safe_reader` | Allow | Deny | P2: uncertified operand streams/list contents plus a protected cwd scope deny. |
| `audit_tar_list_member` | Deny | Allow | P3 explicitly allows archive listing, even when a listed member has a protected name. |
| `git_command_surface_6` | Deny | Allow | P1 explicitly expands the literal alias `alias.x=log`; plain log is a safe form. |
| `policy_v2_tar_1`, `policy_v2_tar_2`, `policy_v2_tar_3` | Deny | Allow | P3/P1 permit literal cat checkpoint/compressor commands over a safe archive-creation scope. Extraction-to-command still always denies. |

`git_grep_timeout` is no longer divergent: P1 denies its indeterminate repository without executing the injected find shim. The other six suite-level external-find divergences remain separate from Go's own fault-injected metadata-scanner tests.

Verification snapshot: the full Go vet/test gate and hook race tests pass, as does `GOOS=windows go vet ./...`. Index fuzzing with checksum-valid mutations passed 587,615 executions in 20 seconds. A 10,000-name v4 index benchmark took about 5.94 ms per parse. Process-launch-inclusive timing measured Claude p99 4.397 ms over 1,486 decisions before the concurrent suite additions, and Codex p99 3.992 ms over 38 decisions. Codex exact checking reports 46 matches and two previously reviewed malformed-patch divergences, with no new differences.

An earlier Claude suite snapshot reported 1,517 matches and 49 assertion differences across 1,566 assertions, including the 25 new differences named above. Subsequent concurrent expectation changes made 17 of those new differences match, but introduced the following differences against unchanged Go behavior. These are not newly introduced Go permission exemptions and were not changed just to match Bash.

| Concurrently changed case | Current suite assertion | Go decision | Existing boundary retained |
| --- | --- | --- | --- |
| `ansi_failure_safe_\000`, `ansi_failure_safe_\036`, `ansi_failure_safe_\cA`, `ansi_failure_safe_\q`, `ansi_failure_safe_\x`, `ansi_failure_safe_\x1f`, `ansi_quotes` | Deny | Allow | Inert escaped-literal and unsupported-escape cases without a content-producing role retain their prior handling. Literal control bytes in command source still deny. |
| `bounded_length_safe`, `bounded_tokens_safe`, `brace_budget_safe`, `deep_safe`, `long_safe` | Deny | Allow | Existing inert-command complexity exceptions remain distinct from the high-risk command-family allowlists. |
| `over_cap_safe_25` through `over_cap_safe_31`, `over_cap_safe_49` through `over_cap_safe_70`, `over_cap_safe_parity_81` through `over_cap_safe_parity_97` | Deny | Allow | The concurrent Bash suite now denies these safe over-budget forms; this task did not remove Go's existing inert/metadata exemptions. |
| `sudo_missing_C`, `sudo_missing_D`, `sudo_missing_R`, `sudo_missing_T`, `sudo_missing_U`, `sudo_missing_g`, `sudo_missing_h`, `sudo_missing_p`, `sudo_missing_u` | Deny | Allow | A missing sudo option value with no executable child retains its prior no-decision behavior. |
| `unclosed_safe` | Deny | Allow | An inert malformed shell fragment retains its prior no-decision behavior; actual hook panics now deny. |

The latest captured Claude run reports 1,476 matches and 90 assertion differences across 1,566 assertions. There are 76 new divergent case IDs relative to the untouched divergence inventory: the 68 cases in the last table, plus `audit_history_safe`, `audit_tar_list_member`, `git_command_surface_6`, `policy_v2_tar_1` through `policy_v2_tar_3`, `xargs_arg_file_safe` and `xargs_arg_file_template`. Exact checking reports 72 unlisted divergences, 70 missing/extra inventory cases and 11 previously listed divergences now matching. The four remaining new divergent IDs belong to the concurrently added cases absent from the assertion inventory. Do not describe this as a green parity gate.

The final full Go gate reports 13 passing packages, 2,225 passing tests/subtests and nine expected skips. Runtime Windows/macOS and isolated provider checks remain CI work; local provider integration tests skip, as do seven existing Bash-only corpus fault shims. Scoped whitespace checking passes; a repository-wide check separately flags trailing whitespace in the concurrently edited Bash hook, outside this task's ownership. No installed-hook or host-cutover claim follows from these synthetic checks.

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

## Policy v2 reconciliation

Parser and analysis-budget failures are not internal crashes: the Bash hook retains
raw protected-witness recovery for demonstrably harmless legacy forms such as
long echo text and missing sudo operands. Unexpected nonzero exits and unbound
variables still deny via the EXIT trap. Unknown wrapper option arities still deny.
Git content from a tracked protected index denies even with a safe pathspec;
archive listing of a protected-looking member is metadata-only. Safe literal
checkpoint and compressor commands pass when inputs are clean; protected child
readers deny. Literal inline Git execution commands are parsed rather than
rejected only because they contain arguments. Go reads local repository alias
metadata without invoking Git. Go and Bash inspect bounded sed script files,
including safe symlinks; unsafe and unreadable scripts deny.
The generated divergence inventory now contains only reviewed find shims,
indeterminate-input tightening and four audit envelopes.
