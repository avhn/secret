# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The first published release is v0.2.3; installed plugin manifests still carry version 0.1.0 and are not release tags.

## [Unreleased]

- Scaffold the Go-only, read-only 1Password backend behind a disabled source gate.
  Add the strict names-only v2 container, immutable registration consent, bound
  fake-op reads, detached bounded subprocesses, exact-byte validation and early
  read-only preflights. Synthetic metadata, launch/redaction and PTY coverage do
  not establish real-provider compatibility. Default registration, discovery and
  reads remain disabled pending pinned provider evidence and licensing review.
  Bash defaults, hooks and plugin manifests are unchanged.
- Add optional staged Go `pass:NAME` support on Linux/macOS for pass 1.7.4.
  Private `NAME.pass-keys` v1 inventories are invisible to unchanged Bash
  discovery. Fresh-account stash/operator transactions reserve before stdin
  insertion, verify bytes before publication, and prove anchored absence after
  deletion, including pass's exit-zero `rm` failure. Freeze GPG options against
  config output/status injection and preserve validated signing fingerprints.
  Metadata remains provider-free; same-name exports compare manifest paths.
  Add synthetic collision/recovery/redaction tests and checksum-pinned native
  GitHub pass/GPG fixtures. Native runner evidence is pending, not inferred from
  local mocks. No Bash CLI, hook policy, plugin or installed-default changes.
  See [pass support and manual recovery](docs/pass.md).
- Add opt-in `age:NAME` encrypted stores to the staged Go CLI on Linux/macOS.
  Pin the reviewed core `filippo.io/age v1.3.2` library. Bounded envelopes bind
  names-only metadata to fully authenticated, warning-free dotenv payloads;
  anchored transactions persist ciphertext only. Add create-only `age-init`,
  proven-candidate `age-rekey`, explicit protected `--age-identity` files,
  names-only inventory/MCP and consent-gated transfers to initialized age stores.
  Reject age-to-plaintext routes, source selection drift and age templates.
  Add synthetic recipient, fault, concurrency, fuzz, Unix PTY and killed-writer
  tests, with module verification and matrix CI gates. Hosted CI remains pending.
  Plaintext defaults, Bash CLI, installed hooks and plugin manifests are unchanged;
  Windows age filesystem operations remain unsupported pending M5a.

## [0.2.3] - 2026-10-24

First published release: reproducible, attested Linux and macOS Go binaries
(opt-in launchers only; installed defaults stay on the Bash CLI and guard).
[Release](https://github.com/avhn/secret/releases/tag/v0.2.3), tag at checksum
commit C `7998002`, source S `7141a13`.


- Apply an owner-approved narrow Bash 3.2 nounset compatibility exception to the
  frozen `hooks/guard-secrets`, with no policy change. Empty array expansions
  retain their intended zero-argument behavior without `unbound variable`
  diagnostics. Stock macOS Bash 3.2.57 CI job `120709429478` correctly denied
  `audit28_t19_find_deadline` but failed on `parts[@]` stderr; the other 5711
  guard cases and the Codex suite passed. Keep decisions, messages and analysis
  budgets unchanged; native CI remains required.

- Reduce staged Go hook over-denials for conditional `cd` chains and literal
  double-quoted arithmetic constants. Directory alternatives stay precise up to
  128 (was 32), with a 16384 per-directory replay budget; exceeding either bound
  still denies. Package-manager workspace proofs keep a separate 32-directory
  bound. Arithmetic commands and C-style loops accept whole double-quoted
  decimal constants, including indices, through shell strings and explicit-shell
  argv. Expansion-bearing operands and single quotes retain the base denials;
  the earlier quoted-command-substitution allowance is dropped. Synthetic
  adversarial cases cover protected alternatives, symlinks, nested shells,
  container binds and recursive arithmetic text on both adapters. The default
  divergence inventory drops 16 literal-quote rows (181 to 165); the retained
  Bash CLI and installed hooks are unchanged, with native CI still required.

- Staged Go hook: deny expansion-bearing operands in arithmetic evaluation contexts
  (arithmetic expansion and commands, `let`, integer declarations and assignments, array
  indices), including implicit integer binds through loops, shell writers and namerefs.
  Unknown writer results cannot certify later bare arithmetic identifiers; unresolved
  declaration options deny. Literal arithmetic controls remain allowed in explicit-shell
  argv. The frozen Bash guard is unchanged.

- `v0.2.2` was tagged at C `68b2cf8` (full C
  `68b2cf8c5e9196f4d79afc032ea95b535751971d`, source S `3001f3c`). Its
  [tag workflow (run 39876942544)](https://github.com/avhn/secret/actions/runs/39876942544)
  passed every job through `release-verify`, but the owner retired the identity
  before approving `release-publish`: a staged Go hook gap involving expansion
  operands in arithmetic contexts, fixed by a later PR, led the owner not to
  publish it. No draft or release exists. The tag ruleset keeps this dead tag;
  never reuse, move or delete it. The owner-approved new release identity is
  **0.2.3**, with a new candidate/source/checksum cycle.
- Run the default shell guard under each test suite's own Bash interpreter so
  stock macOS Bash 3.2 CI also exercises the guard under 3.2. Guard suite failures
  now print the permission decision reason, and empty stdin must exit successfully.

- `tests/go-cli.sh` and `tests/go-hook.sh` now print the last 40 suite log lines (synthetic-
  value lines redacted) to stderr when a suite does not finish or divergences are unlisted.
- Preserve physical symlink-parent traversal in Go Docker/Podman bind sources,
  container reader operands and workdirs before protected-path checks. Retain
  public binds, mount precedence and container-root boundaries, with synthetic
  shell/argv tests on both adapters. The frozen Bash guard remains unchanged;
  native platform CI and installed-host protection are not claimed.
- Close staged Go hook Audit 28 gaps for `uvx` and `uv tool run`: inspect the
  actual child under its directory options and deny protected configuration,
  requirements, env-file and project metadata inputs. Protect relocated gh
  `hosts.yml` selected by inherited, inline, exported and wrapped
  `XDG_CONFIG_HOME`/`GH_CONFIG_DIR`, including aliases and content searches.
  Keep public readers, metadata queries and approved printer transports allowed;
  retained Bash executables and installed hooks are unchanged (merged in #18, CI green).
- Tighten Go coprocess framing and restore redirected simple executable dispatch,
  including patch recipients. Coprocess pipes cannot borrow ancestor heredoc
  proofs. Reject alternate apply_patch argv sources and uncertified patch diff
  inputs even with an explicit output; retain patch help/version, read-only Git
  apply modes and valid public apply_patch heredocs. Synthetic U2/U3 coverage and
  exact Bash differences are recorded; retained Bash and installed hooks are
  unchanged, with native CI and host evidence still required.

- Build and test with Go 1.26.10 instead of 1.26.0: govulncheck found reachable
  standard library vulnerabilities, including `os.Root` escapes (GO-2026-4970,
  GO-2026-4602, GO-2026-4864) on store write paths and `net/url` parsing
  (GO-2026-4601). CI now runs a pinned govulncheck. The dead-tag rehearsal uses
  Go 1.26.10 to reproduce v0.2.2's attested bytes.
- `v0.2.0` was tagged at `29216e7`, but its [tag workflow (run
  39696575366)](https://github.com/avhn/secret/actions/runs/39696575366) failed before
  any release assets, attestation or draft: checkout replaced the annotated tag with a
  lightweight local ref. It is a dead, protected tag that must never be reused, moved or
  deleted.
- `v0.2.1` was tagged at `229ee0e` (full C
  `229ee0ef5a229920f2bbe52f01adce1f7e0ae17c`), but its [tag workflow (run
  39790612288)](https://github.com/avhn/secret/actions/runs/39790612288) failed in
  `release-verify` after successful builds, byte reproduction and attestation:
  gh rejects `--signer-workflow` together with `--cert-identity`. The installer
  had the same conflict. This is another dead, protected tag, never to be reused,
  moved or deleted. The owner-approved replacement identity was **0.2.2**.
- Keep the exact certificate SAN and all source/signer/ref/issuer/runner pins
  without mutually exclusive gh flags; show public gh verification diagnostics.
- Rehearse new verifier and production installer logic on PRs/manual runs using
  reproducibly rebuilt v0.2.2 assets and genuine public attestations, including
  online/bundle verification, retained offline trust and negative cases.
- Restore runner-local annotated release tags after checkout before checking
  their type and final commit; require annotated tags for production installs.
- Upload draft attestation bundles with portable names, byte-compare downloaded
  assets, then restore gh bundle names before final provenance verification.
- Disable terminal echo in the Go CLI before printing the hidden `stash` prompt,
  so input typed between the prompt and the read is never echoed (macOS CI
  witnessed it in the retained `hidden_stash` case). Linux and macOS restore the
  exact prior settings; other platforms keep the previous behavior.
- Let a sole maintainer approve the `release-publish` draft gate: require a
  reviewer and a deployment policy limited to the `v0.2.3` tag instead of
  self-review prevention, which no single-owner repository can satisfy.
- Retry the Go store write lock while Windows reports a pending-delete lock
  directory as access denied, instead of failing a contended writer at once.
- Prepare M4 v0.2.3 Linux/macOS reproducible assets, checksum-only source identity
  checks, scoped final-tag provenance verification and owner-approved draft workflow
  (candidate CI green in PR #9; replacement candidates and publication pending).
- Add opt-in POSIX `bin/secret-go`, `hooks/guard-go` and explicit release installer
  with digest/provenance checks, private cache, offline preinstallation and no
  automatic Bash fallback. Add native install, launcher and synthetic release tests.
- Keep failed hook denial writes on fixed stderr across POSIX shells, including
  closed stdout on macOS. Preserve caller Go caches during launcher tests and
  cover Darwin symlink limits and physical cwd aliases without relaxing rejection.
- Add the inactive, sponsorship-gated real-host harness and PR-only offline
  synthetic classification. No model sessions or installed-host evidence claimed.
- Document installation pins, failure recovery, Bash rollback and release approvals;
  doctor now reports staged tooling without inferring provenance or activation.
- Move all installed-default changes to M4.1: four manifest version bumps,
  `onFailure: "block"`, Claude hook path, `bin/secret` plus `compat/secret`, and
  Go hook output contract. The installed CLI, hooks, manifests and M2 policy
  remain unchanged in M4.
- Tighten staged Go hook raw path limits to 4096 UTF-8 bytes per envelope path
  and patch target, with 255-byte components before normalization (PR #10).
  Reject C0/DEL patch-header controls, including CRLF, and malformed Add/Delete/
  Update/Move bodies, incomplete hunks and misplaced EOF markers. Match upstream
  Codex's optional first @@ marker, empty context lines, public indented headers
  and exact literal EOF wrappers; do not misclassify valid implicit first hunks
  as security tightenings. Patch bodies are grammar data only, never applied or
  repeated in diagnostics. Document each retained security-specific grammar limit.
- Bound Go hook input reading, decoding and analysis together to four seconds,
  retaining independent two-second read and shell-analysis budgets. Delayed stdin
  and late-analysis tests cover fixed single denials; process startup and blocked
  output writes are excluded. The Bash CLI, installed guard and host failure
  behavior are unchanged; hosted CI is green (PR #10).

- Fix staged Go hook over-denials for `python3 -m env`, explicit-file
  `git grep --no-index -q`, and ripgrep quiet/names-only searches with
  `--passthru` (PR #10). Preserve protected pattern-file, content-output and
  credential-module denials. Document the existing match-status/count oracle
  limit and retain conservative mixed-brace selector denial under protective
  ripgrep config. The Bash CLI and installed guard are unchanged.

- Fix staged Go operator PTY tests to drain output through helper exit on macOS,
  with bounded nonblocking input, exit waits and redacted timeout diagnostics.

- Implement the staged Go M3 operator workflow; all applicable hosted CI jobs are green (PR #8).
  Add positional `rotate REF KEY`, `delete REF KEY` and `rename REF OLD NEW`,
  exact hidden controlling-terminal confirmation and hidden rotation input.
  Import dotenv/op/bw with explicit mappings for provider fields; export only to
  implemented Keychain/libsecret destinations with `--on-conflict=fail`.
  Transactions prepare fresh verified accounts, publish the manifest, then remove
  exact obsolete accounts; names-only recovery intent supports manual verification.
- Add versioned names-only inventory, diff, doctor, completion, opt-in rotated audit
  and explicitly allowlisted stdio MCP list/show/diff/health. Metadata may expose
  paths, labels and provider account IDs, never values, hashes or lengths. Preserve
  legacy text show and frozen Bash help fixtures. Clear owned Keychain transport
  buffers and decode byte-oriented provider output without secret string copies.
- Add private `run --template-file` rendering of literal `{{KEY}}` placeholders
  under `HOME/.secrets/.rendered`, independent of `SECRETS_DIR`; pass only
  `SECRET_TEMPLATE_FILE` to the child. Stop the supervised process group before
  normal/error/catchable-signal cleanup. SIGKILL, crashes and power loss can leave
  protected plaintext; cleanup is not secure erasure.
- Add hosted Unix PTY tests, isolated provider operator/argv checks and bounded
  feature fuzzing without replacing existing CI jobs. No Bash CLI, installed-hook,
  M2 policy, plugin or Windows support cutover is included.

- Complete M2: the Go hook (`secret hook claude|codex`) reaches parity with the
  Bash guard under the owner's convergence rule, with 80 reviewed divergences and
  all CI jobs green. The installed Bash hook remains active until the M4.1 cutover.

- Preserve physical `..` traversal after symlinked glob components, including
  wildcard prefixes and missing credential-name context. Apply the same ordering
  to Grep directory selectors, visible search roots and relative ripgrep config
  paths, while retaining native Windows literal-alias lookup and public controls.
  Synthetic paired regressions do not establish installed-host protection.

- Preserve literal glob ancestors for native OS lookup, including Windows 8.3
  aliases and case variants, before enumerating wildcard components. This retains
  protected hidden-directory matches under a sibling HOME and public-glob controls.
  Add an alias/listing mismatch regression that runs on every OS; native Windows
  CI remains a separate gate, with no installed-host protection claim.

- Close confirmation audit 29 protected-read parity gaps in computed Deno argv
  keys, constructor child directories and package executable paths containing
  `@`. Validate expanded patch headers without executing expansions, retain
  quoted Git-write parity, and protect inherited Git-directory roots.
- Inspect opaque extglob substitutions, unsupported deep backquotes and stored
  arithmetic syntax across loops, assignments, appends and branches. Retain
  hidden intermediate glob matches conservatively. Cap interpreter literal work
  before metadata scans and bound raw-body regex work within the shared analysis
  deadline, preserving decoded literal boundaries and inert writer bodies.
- Certify public Parallel null-option and fd producer pipelines in Bash while
  retaining protected scopes and metadata-child roles. Record exact supplemental
  Bash over-denials separately from Go tightenings without weakening assertions.
  Audit 29 malformed-input and raw-limit follow-ups remain explicit M2.1 work;
  local synthetic checks do not establish CI or installed-host protection.

- Close a3b0306 review gaps in patch stdin certification and capped brace scans:
  distinguish stdin heredocs from other descriptors, reject opaque effective
  patch streams after pipes or file redirects, and preserve brace-budget denials
  through best-effort Bash argument analysis. Add synthetic regressions for both
  adapters without changing installed hooks or claiming host protection.

- Close confirmation audit 28 launch and syntax parity gaps: preserve Deno argv
  witnesses across unrelated options, recognize PHP literal array constructors
  and consecutive numeric argv keys, retain attached env split-string operands,
  and scope systemd-run configured credential paths to its child. Reject invalid
  timeout, taskset and setsid launches, hidden substitutions in parameter words,
  quoted arithmetic operands, misplaced reserved words and commandless coprocesses.
- Validate shell-fed patches after wrapper dispatch with effective cwd and stdin
  scope, retaining protected symlink targets and valid shadowed-heredoc controls.
  Apply Grep checks on both hosts, default only absent output modes, split selector
  lists without dropping whole-selector denials, and fold configured-path case
  comparisons on every OS. Bound root-glob recursion, Grep selectors and braces.
- Bound Bash first-line extraction, credential-selector suffix work and brace
  enumeration within existing deadlines. Validate arithmetic commands and loop
  clauses without evaluation, preserving quote removal and continued loops.
  Refresh exact inventories and denied-command fixtures; retain named Go
  arithmetic/function/time over-denials rather than weakening existing denials.
  Synthetic replay does not establish installed-host or cross-platform protection.

- Close confirmation audit 27 guard differences with bounded interpreter source
  roles, qualified Deno constructors, case-insensitive PHP launches and literal
  PHP/Node/Bun child directories. Reject missing required interpreter operands
  and unterminated executable literals without treating script arguments as code.
  Retain optional Perl -F and LuaJIT -O operands and ordinary quoted data.
- Carry xargs filename-input provenance through wrappers and redirects, replacing
  inherited stdin provenance at pipeline recipients. Model UV and systemd-run
  child directories and Docker directory-bind reader aliases, including short
  option clusters, while retaining public mounts and env-file consumers.
- Inspect full array assignments and bounded unquoted field splitting, including
  known empty IFS, without treating inert IFS text as a mutation. Validate Bash
  function, time-pipeline and arithmetic increment framing in Go. Protect Git
  directory destinations and share XDG file-tool path normalization.
- Bound Bash CRLF normalization, preprocessing, decoded argv and file-tool paths
  before expensive analysis. Reject control-bearing tool names and malformed
  arithmetic, parameter expansions and patch envelopes. Certify harmless literal
  recursive eval without execution, retaining protected, dynamic and depth-limit
  denials. Validate patch EOF markers in update hunks on both Go adapters and
  reconcile the former Bash malformed-patch exception. Keep existing deadlines.
- Retain the per-analysis Go cwd-resolution cache and normalize BSD wc padding in
  synthetic guard-context checks. Refresh inventories and denied-command metadata;
  native platform CI and installed-host evidence remain separate release gates.

- Probe each Bash Git write-target candidate once and cache Git-path anchor
  context per decision, removing duplicate metadata work that exhausted the
  shared deadline on stock macOS Bash 3.2 for Ruby interpolated-regex literals.
  Add synthetic cache, scope, failure and deadline controls in CI.

- Normalize Go interpreter member chains across spaces and newlines before
  literal launch classification. Split attached and clustered executable-code
  options through a shared interpreter grammar, retaining both JavaScript -pe
  witnesses and stopping at value-taking flags, including Ruby encoding operands
  and optional numeric clusters. Cover Python/PyPy, Ruby, Perl,
  JavaScript runtimes, Lua/LuaJIT, PHP, Rscript and awk/gawk, while preserving
  positional jq/yq filters. Add protected-launch and must-allow regressions for
  both host adapters, string/argv envelopes, env wrappers and executable stdin,
  with quoted API text, comments, regex data and public commands kept inert.

- Share Go interpreter literal metadata and Git configuration-path proofs across
  sibling child analyses, avoiding repeated filesystem lookups at the 256-literal
  boundary on slow runners. Keep cwd and effective configuration paths in cache
  keys, retain lookup-error denials, and discard caches between analyses. Report
  exhausted analysis deadlines as indeterminate rather than protected-file
  witnesses. Add deterministic simulated-slow-resolver and cache-scope controls
  without raising work limits or changing the boundary allow expectations.

- Bound Bash raw protected-name scanning, interpreter Git-path extraction and
  physical ancestor resolution with subprocess alarms and the shared decision
  deadline. Match filename word runs once rather than retrying every suffix of
  long dotted-call literals, and deny incomplete raw scans in every caller.
  Preserve public literal, filename-suffix and inert writer controls, with
  four-second Node/Python heredoc regressions and injected scanner timeouts.
  Cap unnormalized envelope paths before filesystem work. Validate confirmed
  shell framing with
  a bounded noexec parser, denying unfinished operators and compound commands
  without executing source. Keep heuristic literal scans best effort, retaining
  printer witnesses before malformed trailing text and allowing printed prose
  without treating it as shell source. Explicit shell children remain strict.
  Normalize Ruby executable/argv0 pairs, PHP proc_open arrays and Deno.Command
  option-object argv through the bounded interpreter literal scanner and shared
  child classifier, preserving public readers, nested option data and inert API
  text. Add strict-deadline synthetic regressions for long quoted heredoc literals and
  redundant cwd/workdir components, with ordinary literals, printed Python/Node
  data, paths and complete shell constructs retained as must-allow controls.

- Close Go confirmation-audit launch gaps through full interpreter child
  dispatch, including archives, multicall applets and gmake. Retain Lua long
  strings and recognize Ruby executable/argv0 pairs, PHP proc_open arrays and
  Deno.Command option-object argv without treating comments or quoted calls as
  executable APIs. Preserve declarations, cwd changes and pipeline scopes in
  fallback shell source, including single-word Lua printers. Keep completed
  argument witnesses before malformed trailing text without promoting prose
  operands into launches or unresolved words into source builtins. Scan executable
  JavaScript template interpolations within shared budgets and preserve escaped
  interpolation in quoted heredocs. Retain Deno argv across shorthand options.
  Scope sudo environment assignments to its child, check Parallel readers against
  listing producer roots, and inspect every repeated executable option, including
  make/gmake short-option clusters, before allowing a command. Preserve public
  reads, metadata, prose and safe repeated values with synthetic analyzer and
  host-envelope tests.

- Restore recursive-search protection in Bash interpreter backticks and Lua long
  strings, retaining conservative witnesses for unextracted source and allowing
  literal names/count/quiet searches. Give Go the same Lua literal boundaries.
  Resume scanning after Lua block comments, including same-line code, and deny
  unterminated block comments. Distinguish Perl quote operators from autoquoted
  keys and method names, keep later launches visible, and deny unterminated
  operators in both guards. Skip whitespace-separated Perl comments to the real
  quote delimiter without treating hashes inside that literal as comments.
  Scan interpolating Ruby/Perl regex bodies for nested launches under existing
  depth/deadline limits and a cumulative regex-work bound. Retain Bash's raw
  recursive-search denial for inert regex data in Go, while preserving ordinary
  regex controls and avoiding false shell-path and glob interpretations
  of interpreter syntax. Make indeterminate Go producer input deny locally as
  well as at the final shell uncertainty check. Add synthetic deny and must-allow
  envelope coverage for both adapters, without executing candidate source or
  reading real stores.

- Reuse immutable denied-command fixture snapshots within a corpus run, with
  separate trees for case-specific search inputs. Check unsupported Windows
  fixture names before creating partial trees, preserving existing skips and
  variant expectations. Disable result caching for the Windows policy CI step
  so cmd/go does not recheck disposable filesystem inputs after reporting test
  success. Exercise fuzz seeds with a native absolute cwd on every platform and
  check nested analysis after sequential metadata and configured-path changes.
  Production policy decisions are unchanged; Windows runtime validation remains
  a separate runner gate.

- Harden Bash printer detection across unknown and interleaved options, cover
  ECR Public and STS role/federation output, and retain only direct stash/login
  sinks. Track reader aliases and uncertain directory effects while preserving
  private eval subshell cwd and child/function alias scopes. Keep corpus capture
  separate from real direct-envelope guard decisions. Deny malformed nonempty
  envelopes before byte loss,
  protect AWS configuration and configured credential paths, and share reader
  metadata checks with interpreter literals and oversized heredocs. Resolve
  missing configured targets through aliased ancestors on both configured and
  reader paths. Expand bounded static variables in executable here-strings and
  unquoted heredocs without running source; preserve quoted-heredoc literals
  and deny indeterminate interpreter stdin. Deny failed shell analysis without
  a raw-scan allow fallback; normalize printer option operands and clusters,
  derive launcher children through full command roles, and apply child cwd
  options across incoming directory alternatives. Cover Lua/Rscript environment
  access and legacy tar stdout bundles while preserving metadata, ordinary
  launcher children and supported ANSI-C literals. Parse complete Parallel
  templates, attached job counts, taskset hexadecimal masks and CPU-list flag
  clusters, make directory-option clusters, and versioned Lua/LuaJIT input.
  Preserve ordinary Docker actions and distinguish resolved credential actions
  from printer-like data operands. Normalize boolean printer flags and kubectl
  content formats, cover op OTP/raw signin, and classify literal interpreter argv
  launches and normalized command strings. Check curl file URLs and JSON/config/
  write-out inputs plus gh API input files while preserving literal curl payloads.
  Union configured credential paths at branch joins, share recognized child roles
  through unknown launchers, and reject mistyped file/search/workdir envelopes.
  Require NotebookEdit's authoritative notebook_path and ignore unrelated
  file_path values when selecting its target. Preserve sequential configured-path
  replacement and singular AWS filenames across branch alternatives. Cover GH
  attached inputs, unknown-launcher Lua aliases and curl URL queries without
  treating user-agent strings as file inputs.
  Cap raw envelopes before expensive parsing. Skip inert interpreter comments
  and quoted calls, cover parenthesis-free Ruby/Perl launches and inline kubectl
  custom columns, and retain whole AWS paths containing colons at branch joins.
  Normalize curl option clusters, multipart/header readers and escaped file URLs
  without treating literal option values or name=content payloads as inputs.
  Validate Grep field types and require the authoritative NotebookEdit target.
  Strictly validate complete envelopes, rejecting non-JSON numbers and unpaired
  escaped surrogates in keys and values before jq. Reject workdir controls before
  extraction. Match Go's 1 MiB plus 64 KiB envelope cap, bound validation keys,
  tokens and nesting, and include preprocessing and file-tool exits in the
  decision budget while retaining bounded names-only operation without Perl.
  Stop shared path normalization on budget exhaustion, propagate failures to
  file-target checks, and preserve valid numeric/scalar metadata and spaced JSON
  arrays in the no-Perl path. Count all interpreter literal scanning against the
  shared decision deadline, stop consuming literals on exhaustion, and propagate
  failed reader and configured-path normalization without empty-path fallbacks.
  Bound preliminary fanout and tokenizer control scans in small chunks, and
  reserve a coarse-clock tick for Bash 3.2 to emit its decision before timeout.
  Bound shared substitution collection and nested parsing between budget checks,
  skip collection without expansion markers, and repeat strict four-second inline
  and here-string regressions with escaped-parameter controls.
  Resolve configured scalar paths before declaration checks, recognize export -n
  options, and classify interpreter recursive search output through shared roles
  so public reads and names/count/quiet controls retain both-adapter parity.
  Normalize PyPy aliases, Perl quote-like literals and Ruby popen argv arrays
  through the shared interpreter and child classifiers.
  Add permanent Claude/Codex regressions,
  must-allow cases and exact platform inventories.

- Bound shared Go interpreter literal scans to the retained source, separator
  and closed-literal ceilings, including stdin and producer adapters. Keep the
  older missing-file allowances as explicit reviewed Go tightenings.

- Classify Go token printers through unknown and interleaved options without
  widening direct login/stash transports. Track literal reader aliases and
  uncertain alias directory effects, including eval definitions, while retaining
  precise subshell and command-substitution cwd semantics. Deny malformed
  nonempty envelopes, protect AWS configuration and configured credential paths,
  and share credential checks across interpreter literals, decoded stdin producer
  arguments and historical Git operands. Keep cwd uncertain for wrapped uses of
  directory-changing aliases; recognize additional ECR and STS credential printers.
  Preserve stdin source checks through wrapped, grouped and aliased interpreters,
  expand bounded static here-string/heredoc variables without executing source,
  and protect inherited AWS credential entries in Git indexes. Keep long public
  interpreter prose readable without weakening plausible-path metadata checks.
  Preserve native Windows absolute reads, canonicalize short-name configured paths, and accept
  drive-qualified sed filenames without relaxing script grammar. Retain canonical
  ancestors for oversized configured filenames without relaxing metadata errors
  for ordinary readers. Bound ancestor canonicalization and synthetic subprocess
  lifetimes, and isolate verbose Windows policy CI with job and test deadlines.
  Normalize global, interleaved and clustered printer options, boolean op cache
  flags and post-terminator actions; reuse child roles through execution launchers
  and honor command-scoped directory options, including clustered make options.
  Check normalized curl file inputs, write-out format files and multipart header
  files on literal fields. Check literal printer commands in interpreter bodies,
  including Lua and Rscript environment access, without treating incomplete
  launcher prose as a printer. Accept attached optional watch differences values.
  Cache physical path metadata per
  analysis without discarding configured witnesses or errors; give Windows policy
  CI a 40-minute test deadline within a 45-minute step.
  Resolve audit 21 parity for failed parses, reserved ANSI-C bytes, Parallel
  templates and attached job counts, external time options, makefile input
  boundaries, Docker file inputs, single-action printer options and versioned
  Lua/LuaJIT. Preserve ordinary launcher and attached-makefile controls without
  adding new reviewed divergences. Honor yarn --cwd for implicit children,
  normalize case-insensitive boolean printer flags, cover secret-bearing kubectl
  output variants and op OTP/raw sign-in output, and classify fully literal
  interpreter argv launches with shared child roles. Check one-slash file URLs
  and --url curl inputs. Reject unpaired JSON surrogate escapes and malformed
  file-tool targets or optional path/output/workdir field types, retaining
  public-file, non-printing and direct-transport controls. Keep interpreter
  comments and regex literals language-aware across inline and stdin source,
  retain uncertain decisions for identified literal argv launches, and recognize
  bounded parenthesis-free Ruby/Perl system and exec lists. Preserve genuine
  comments, ordinary launcher prose and public-child controls. Tokenize Python
  triple-quoted strings atomically, normalize PyPy aliases across interpreter
  roles, and send identified literal shell launches through full child policy
  without reclassifying arbitrary prose. Resolve gh API field-file actions after
  global options and deny control bytes in decoded curl file-URL paths. Add
  synthetic Claude/Codex deny and must-allow regressions for confirmation audit 23.
  Classify Python os.popen shell children and normalize static Python raw, bytes,
  Unicode and formatted literal prefixes with Python escape rules. Keep dynamic
  interpolation unknown and Python/PyPy exec source out of shell-child analysis
  while preserving interpreter-source checks and Ruby/Perl/Node shell launches.
  Match Bash's global envelope key, punctuation-token and container-depth bounds
  before unmarshaling. Bound unnormalized path separators before redundant
  components disappear, retaining ordinary public-path and metadata controls.
  Share Bash's broad interpreter literal fallback across Python/PyPy, Node,
  Bun, Deno, Ruby, Perl, PHP, Lua and Rscript. Classify recognized child-command
  literals through full shell policy even in unfamiliar APIs; retain unrecognized
  prose and harmless child controls. Cover list-first and Ruby positional spawn,
  static JavaScript templates and Perl quote-like literals. Retain command-prefix
  witnesses when interpolation prevents static argv certification, using
  language-specific string rules. Reject interpreter recursive-content searches
  without relying on the current tree, which preceding code may populate.
  Apply Bun --cwd before runtime-code and child dispatch, preserving invocation
  scope and public-file controls. Preserve configured credential paths through
  value-less declarations and bounded quoted/unquoted HOME expansion, including
  declare and export -n; deny unresolved configured assignments. Keep
  absent cwd-relative credential targets protected and reject explicit HOME/.aws
  content searches even with certified rg exclusions. Bound initial envelope reads
  to two seconds, requiring EOF and denying read failures without delayed output.

- Keep the Bash cwd after bounded inert literal eval source, retain denials for
  dynamic source and directory/function effects, and use Bash 3.2-safe empty
  array expansions. Preserve literal Kubernetes and HOME metadata in generated
  denied-command fixtures and check audit 19 directional parity.
  Close regenerated-corpus gaps for multiple/relocated function directory effects,
  doctl verbose flags, and protected historical Git blobs in log/blame operands.
  Retain npm global exec options and operand-free pnpm scripts in wide projects.
  Check configured Kubernetes paths against Git indexes after later assignments.

- Retain Bash protection for historical Git blob operands, refresh relative
  Kubernetes credential witnesses at reader cwd scopes, and recognize physical
  credential aliases and global-option token printers. Avoid workspace scans
  for operand-free pnpm script fallbacks; add Claude/Codex review regressions.

- Harden Bash credential-file coverage, ack search scopes, token printers and
  direct login transports, function cwd unions, and package-exec workspace and
  option roles. Preserve public templates and project Yarn configuration, and
  add permanent Claude/Codex cases with exact platform inventories.

- Expand Go credential-file and token-printer coverage, including literal Kubernetes
  config paths in filtered listing streams, recursive ack searches and direct
  password-stdin sinks. Normalize global printer options between subcommands.
  Preserve eval directory effects and distinguish workspace names from paths;
  reject protected indexed Git reads while retaining documented env-template reads.

- Close Go package-exec parity gaps for pnpm shell mode, npm prefix and workspace
  selectors, and keyring backend/path options. Bound unresolved workspace scope
  using directory metadata, keep child directories out of sibling commands,
  retain npm script data operands, and refresh audit 18 platform inventories.

- Harden Bash credential-path normalization, package shell-mode and workspace exec
  scopes, npm/dlx option roles, Git listing pathspecs, function-local directory
  changes and keyring options; retain ordinary developer runner commands.

- Harden Go xargs listing streams over every producer root, package shell-call
  slots, backgrounded directory changes, fdfind execution and keyring printers.
  Continue ripgrep ignore-override checks above work trees to the filesystem root
  under a fixed bound; retain public filtered find/fd and package-runner forms.

- Harden Bash xargs producer-root and physical-path certification, shell-call runners,
  dot-segment credential paths, compound-command cwd, mixed brace globs, ancestor
  ignore overrides, npm/dlx option roles, fdfind execution and keyring printers.

- Stream synthetic variant-generator commands into jq instead of argv, including
  1 MiB cases, and keep its direct-call stub compatible with suite assertions.

- Fix Go future-Git-directory protection across canonical cwd aliases and keep
  unmatched Windows credential-glob witnesses in their slash-qualified path role.
  Protect Windows alternate data streams by their base file, harden filtered
  find/fd and negative-glob scopes, and refuse ripgrep ignore certification when
  higher-priority ignore files may restore credentials. Restore Python module
  and npm x runners, attached rg types, quiet searches, Markdown/subtree Grep
  filters, and bounded cwd alternatives after blocks and conditionals.

- Harden Bash negative search filters, ripgrep ignore certification, fd roots, npm runner options, reader flags and uncertain cwd; restore typed/subtree searches and launcher data operands, and remove redundant long-option Git probes behind the filtered-header flake.

- Harden Bash guard launcher slots, fd execution, message-file roles, conditional cwd and secret printers; protect `.envrc` and restore filtered searches, names-only output, ignored Git paths and runner forms.

- Harden Go launcher, heredoc, fd execution, Kubernetes output and archive
  roles; protect direnv `.envrc` files and certify filtered search scopes.
  Bound conditional-cwd analysis with deduplicated directory sets and preserve
  Windows non-path data operands without relaxing permission or I/O failures.

- Preserve unmatched credential-glob context in Go, check every fd extension
  alternative, and keep ripgrep JSON output outside count-only exemptions.

- Classify conditional working directories, future protected-name globs,
  command-word environment printers, package runners and secret output flags.
  Treat quoted heredoc commit/PR bodies as inert data outside the 8 KiB Bash
  analysis limit; keep benign config getters, names-only searches and env-file
  consumers available. Document two-second analysis denials.

- Tighten Bash guard reader options, credential printers, Git grep and scoped
  searches. Allow unmatched credential globs and TypeScript-only searches
  when no protected TypeScript files are present; reject malformed envelopes.

- Harden the Bash guard for inline code targeting independent Git directories,
  bind mounts, Git configuration overrides, Make recipes and options, and
  ordinary upload and environment-printing commands. Restore safe developer
  Git, search, and message commands, and bound oversized single-line analysis.

- Scan protected-name and Git configuration tokens in unknown shell arguments,
  shell input bodies, inline code and strict command slots. Modelled metadata,
  store and env-file operands retain their earlier decisions. Sudo shell-option
  clusters now deny.

- Harden Bash guard handling of independent Git directories, Git apply options,
  templates, shell stdin, command slots, launchers and bounded shell analysis.
  Add synthetic guard regression cases for these paths and common safe forms.
  Over-budget requests and xargs readers of external input now deny; inert
  quoted heredoc file writes remain allowed up to 1 MiB.

- Bash guard protects independent Git directories and Git configuration tokens
  in attached options and inline code, rejects interactive launchers and
  unverified command slots, and handles nested coprocesses, shell option
  terminators, static-variable reassignment, and bounded token streams. Its
  synthetic regression inventories cover the audit 10 additions on Linux and
  macOS. Ordinary non-executing argument prose remains allowed.

- Bash guard scans tracked names across the full work tree even when launched from a subdirectory, and denies sed device and process file operands.

### Added

- Bounded Go Codex patch-header checks for add/update/delete/move paths, physical aliases and explicit workdirs, with malformed patch denial and synthetic fuzz coverage; installed hooks remain unchanged.

- Default Go hook Bash AST analysis with 64 KiB envelopes, 40 KiB fragments, explicit wrapper and grep/sed/split option arity, scoped directory checks and value-free denials. The installed Bash hook and plugin manifests remain unchanged.
- Mechanically generated denied-command variants, 76 permanent synthetic audit envelopes, and exact reviewed default-hook divergences with no pending-M2 categories. See the [tightening table](docs/design/hook-tightening.md) for deliberate differences and local evidence.

- Bounded Go PreToolUse envelope and protected-path checks with `secret hook claude|codex`, synthetic decoding and alias tests, fuzz seed, and exact Bash-vs-Go hook case inventories. The active installed hook remains Bash; default Go shell analysis and search certification are now ready for review.
- Alternate `SECRET_CLI` executable support for the CLI and provider shell suites, a tagged disposable Go backend stub, and per-case Go divergence checking in CI on the existing runners. The default Go build ignores stub environment variables.
- Focused Go checks for stub isolation, failure injection, private secret directory permissions and unlabeled stash section reset.

- Unix Go run and exec child environment selection, two-stream literal filtering and supervised child execution with synthetic Bash run goldens. Windows rejects both until its separate child-supervision gate.

- Machine-checked synthetic shell case inventories with a Go format test and isolated provider CI checks.

- A Go module skeleton and Go CI on Linux, macOS and Windows runners.
- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Fixed

- Bash guard inspects shell commands beneath unmodelled wrappers and coprocesses, rejects unverified shell stdin and Git submodule foreach, resolves Git configuration write paths through ancestor gitfiles and home variables, and checks MultiEdit and NotebookEdit paths. Expanded permanent audit cases cover read-only common forms and Git write tools.

- Bash guard denies stdin shell scripts, applies a conservative sed allowlist, prevents ordinary writes to Git configuration, and hardens Git subprocess lookup and submodule classification.

- Bash guard isolates bounded Git probes from repository config and process-group signals, rejects alternate-index and config-write ambiguity, and tightens dashed Git, pager/editor, shell stdin, globstar and ambiguous sed write-flag analysis.

- Bash hook rejects every non-inert inline Git configuration key, disallows command-text editor and pager interpreters and Git SSH/diff/askpass overrides, and conservatively rejects ambiguous sed grammar. Literal allowlisted editors and pagers remain available.

- Bash guard now denies custom Git aliases without reading Git configuration, analyzes additional shell applets and quoted option names, parses sed scripts before accepting them, and treats indirect environment assignments as uncertain for subsequent consumers.

- Shipped Bash guard closes multi-exec find, attached and multiline sed reads, cdable-variable directory changes, and BusyBox tar stdout extraction. Custom Git aliases are denied; inline transport configuration and indeterminate object sources deny content reads, while inherited editor and pager settings no longer block ordinary Git commands.
- Shipped Bash guard now emits a denial for malformed nonempty requests and analysis errors, gates content-producing Git calls on bounded tracked index names, checks command-running options and inherited editor settings, and tightens find, xargs, archive, directory stack, proc/dev, jq, sed and awk inputs. Ignored untracked files do not block safe Git history forms.
- Ripgrep configuration certification now resolves only its own config path instead of running a platform-dependent directory scan on a single file.
- Shipped Bash guard now denies control bytes, bounded Git history and archive reads, unsafe shell hook variables, interpreter environment and literal script readers, indented Codex patch paths, and audited reader-option, cd, find and glob bypasses.

- Installed Bash guard now denies protected Git grep pager searches, clustered grep/sed file inputs, cd option traversal and brace-expanded Grep selectors.

### Changed

- Go stash now protects the designated secrets directory, correctly resets an unlabeled stash following a labeled section, and matches the Bash stale-lock timeout hint. The tagged stub rejects invalid backend bytes and supports put, get and manifest-publish failure injection.

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Bounded Go provider output and inherited-pipe waits, with Unix process-group cancellation. Go run now times out blocked output sinks, selects child commands using the constructed PATH, and validates usage before Windows launch rejection. Missing option arguments exit 1 like Bash. Replaced repeated redaction rescans with a streaming matcher.

### In progress

- M2 default-hook parity and hardening are ready for review, not a host cutover. Fixed config reassignment, wrapper clusters, previously unwalked AST expressions, printer-pipe redirects and assignments, combined printer flags, symlinked ancestors before parent traversal, Grep selectors, and tar mode parsing. Local Go, race, fuzz and retained Bash checks pass; real-host and cross-platform gates remain pending.

- Go inventory and human-only CLI commands have synthetic Bash-generated parity cases and CI drift checks; usage exits 1 like Bash, Unix run and exec now have synthetic Bash goldens, and the Bash CLI is still active.
- Go libsecret and Keychain transports now use stdin-only value writes, exact service/account lookups, and disposable provider integration tests in CI; provider validation is pending isolated runners.
- Go store writes now use an anchored parent for private atomic replacement and the shared Bash secrets-directory lock for file and backend transactions, alongside validated v1 manifests, with Bash-generated stash byte goldens and process-concurrency checks. Backend dispatch has a test-only directory stub, readback-before-publish ordering, and unsupported real-provider placeholders; the Bash CLI remains active.
- Go file-store parsing, resolution, label selection, and merge helpers have synthetic tests and Bash-generated golden assertions, including an extended selection corpus and CI drift check; runner validation remains pending.
- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); v0.2.3 is published, and no Go cutover is claimed.
