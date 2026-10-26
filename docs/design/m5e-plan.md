# M5e plan: bounded PowerShell classification and Windows host evidence

Status: draft for owner approval (2026-10-26), revised after gpt-plan-reviewer review. No code lands until the owner approves
this plan and the parser revision below.

M5e adds conservative PowerShell classification to the staged Go hook, replacing Windows
shell refusal only for a verified host/dialect contract. Completion requires actual
Windows host evidence that missing, crashed and timed-out hooks block execution. Parser
tests alone cannot satisfy this milestone. This plan authorizes no installation, release,
promotion, authenticated session, commit or push.

## Scope, baseline and binding revisions

- Baseline: main at `8b497ae`; Windows amd64, Go 1.26.10, `GOTOOLCHAIN=local`. M5a
  supplies native file identity and path checks. Preserve the frozen Bash guard,
  installed manifests, `hooks/hooks.json`, CMD denial, Unix Bash behavior and exact
  existing inventories. M4.1 remains separately blocked and owns installed activation
  and output-contract changes.
- Discovery: `internal/hook/hook.go` dispatches only `Bash` as a shell, and
  `internal/hook/input/input.go` requires commands only for `Bash` and `apply_patch`. A
  documented Claude `PowerShell` event currently falls through without a decision. The
  installed `hooks/hooks.json` matcher is `Bash` plus file tools, so the installed Bash
  guard is not invoked for the Claude PowerShell tool either. Windows is not a supported
  install target; manifest matcher changes belong to M4.1 and owner approval. Step 2
  adds Windows recognition and default denial in the Go hook before any allow; matching
  an event inside Go cannot compensate for installed matchers that never invoke it.
- Budget: `internal/hook/input/budget.go` caps raw envelopes at 1 MiB + 64 KiB; Bash
  also has an 8 KiB ordinary-source policy and larger-source handling. Preserve those
  contracts. Add a 64 KiB raw-envelope ceiling for Windows shell events and a 40 KiB
  decoded PowerShell-source ceiling, including aggregate nested source. Do not shrink
  shared Bash, file or patch limits.
- Binding revision requiring approval: `docs/design/go-rewrite.md` section 9 specifies a
  runtime PowerShell parser helper. This plan replaces it with a bounded Go safe-subset
  parser plus a test-only real-PowerShell oracle. Update that section in the contract
  commit; this is not the existing approved design.

```text
Before: envelope -> Bash on Windows -> fixed deny; PowerShell -> unhandled/no decision
        file/patch -> M5a native identity checks; installed defaults -> unchanged Bash
After:  envelope -> host/tool/contract gate -> unknown, Bash, CMD -> fixed deny
        verified PowerShell -> bounded Go AST -> explicit roles -> M5a paths -> decision
        test-only PowerShell ParseInput oracle -> differential evidence, never execution
        real-host failure gate pending -> production PowerShell allows remain disabled
```

## Parser and failure contract

- Choose a Go-native lexer/parser for the strict grammar below in `internal/hook/ps/`.
  It classifies deterministically in process, without runtime PATH lookup, PowerShell
  availability, startup latency, subprocess trust or a shipped helper asset. Its risk is
  disagreement with PowerShell syntax, so structural differential checks are required,
  not matching allow/deny totals. Unknown syntax always denies.
- Runtime `ParseInput` offers authoritative grammar but needs a fixed trusted
  executable, matching edition/version, bounded stdin and AST-summary output, profile
  isolation, process-tree cleanup, crash/timeout handling and cold-start headroom within
  the hook deadline; any helper failure would deny. That runtime surface is unnecessary
  for this subset. Do not implement both or add a production fallback.
- Reuse the bounded decision/output ownership in `internal/hook/hook.go`: two-second
  input read, two-second analysis budget, four-second overall deadline. Parser caps:
  4,096 tokens, 2,048 AST nodes, 256 words per command, four nested script-block levels,
  counted across the whole request. Check deadlines while scanning, parsing, walking and
  before every allow. Exhaustion, malformed input and panic return fixed value-free
  denial; no raw source, parse errors or paths in diagnostics or audit.
- The test-only oracle calls `[System.Management.Automation.Language.Parser]::ParseInput`
  and inspects the returned AST, tokens and parse errors. It never invokes candidate
  text, `Invoke-Expression`, a compiled script block, `SafeGetValue`, dot-sourcing or
  imports. Synthetic UTF-8 source goes over bounded stdin to a fixed committed script,
  not argv, using explicit executable paths, `-NoProfile -NonInteractive`, an isolated
  cwd and environment, bounded capture and a process-tree timeout. Oracle absence,
  malformed output, crash or timeout fails required CI rather than skipping.
- Go recovery handles recoverable analyzer panics, not fatal runtime exits or failed
  startup. The development shim denies a detectable missing binary; post-start crash,
  unavailable launcher, unwritable output and host timeout require verified host
  blocking. Preserve the current output contract; if Windows host evidence cannot pass
  without M4.1 changes, leave the host gate blocked.

## Host, version and working-directory contract

- Claude documents a native `tool_name: "PowerShell"` with source in
  `tool_input.command` and optional `description`, `timeout` and `run_in_background`;
  `Bash` stays distinct. Windows selects `pwsh.exe` for PowerShell 7+ and falls back to
  `powershell.exe` 5.1; profiles are not loaded. The hook configuration's
  `shell: "powershell"` selects the hook runner, not the tool dialect. No documented
  field identifies the edition/version or a per-command workdir, and current docs are
  not evidence for the pinned Claude executable.
  [Claude hooks](https://code.claude.com/docs/en/hooks#powershell),
  [tools reference](https://code.claude.com/docs/en/tools-reference#powershell-tool).
- Codex documents shell commands and unified `exec_command` as hook name `Bash` with
  `tool_input.command`, with no Windows PowerShell discriminator or per-command workdir.
  Do not parse a Windows `Bash` event as PowerShell because of the OS or default shell.
  Keep Codex Windows shell calls denied until pinned-host evidence establishes a
  distinguishable dialect and effective cwd.
  [Codex hooks](https://learn.chatgpt.com/docs/hooks),
  [Windows documentation](https://learn.chatgpt.com/docs/windows/windows-sandbox).
- Target the common subset of Windows PowerShell 5.1 and PowerShell 7.x. Oracle lanes
  use `powershell.exe` 5.1 and an explicitly pinned stable `pwsh.exe` 7.x patch; record
  full versions, paths, runner image and OS build. Pick and verify the 7.x patch in step
  1, not `latest`. Claims cover only tested versions; upgrades need renewed evidence. No
  PowerShell enablement on Unix or WSL.
- `internal/hook/hook.go` ignores its host argument during classification today. Make
  host identity participate in Windows shell routing; validate a PowerShell string
  command, never stringify argv. Keep native Windows `Bash` strings/argv, nested shell
  launches and CMD denied. Unknown host or dialect, conflicting metadata and missing
  commands deny. No agent-supplied `shell` field or syntax guessing authorizes anything.
- A host contract names the exact host/package version, tool name and source field,
  PowerShell edition/version, fresh no-profile behavior, command-resolution assumptions
  and effective cwd. Production routing stays disabled until that contract and the
  failure gate are evidenced; tests use injected internal seams, not an environment
  escape hatch. Envelopes lack version fields, so the deployment must pin host and shell
  externally; the hook cannot authenticate versions from JSON.
- Require a valid native absolute envelope cwd and a valid home from `paths.Home()`. A
  typed nonempty workdir is anchored against envelope cwd with native file semantics;
  absent workdir means cwd only after that host's execution proves it. Reject unanchored
  or provider cwd, drive-relative paths and ambiguity; never use the hook process cwd.
  Codex's omitted-workdir gap blocks enabling its adapter.

## Safe subset and role mapping

- Parse complete input with lossless token spans: plain command invocations,
  semicolon/newline statement lists, single-quoted strings with doubled-quote escaping,
  non-expanding double-quoted strings, conservative bare literals, pipelines and modeled
  redirects. Support LF/CRLF and bounded comments with oracle tests. Reject unsupported
  backtick forms, Unicode quotation or operator substitutes and control characters
  rather than normalizing them. Active `#requires` directives (anywhere, including
  nested text) and signature blocks deny; ordinary comments are controls. The oracle
  requires a null root `ScriptRequirements`, and the host contract records the actual
  execution framing (command string versus script file), since directive effects depend
  on it. Variables, interpolation, subexpressions, concatenation,
  arithmetic, member access, type literals and expressions are outside the grammar.
- Initial command allowlist: `Write-Output` with literal data, `Out-Null`,
  `Get-Content`, `Select-String`, `Get-ChildItem -Name`, narrowly modeled `Copy-Item`,
  `Set-Content`, `Add-Content`, `Out-File`, and `ForEach-Object` with one literal script
  block. Each command has explicit parameter sets, exact spelling, arity, positional
  roles and input/output contracts in `internal/hook/ps/roles.go`. Unsupported
  parameters, abbreviations, duplicate or conflicting bindings, unmodeled common
  parameters and unknown commands deny. Bash option parsing is not reused.
- Case-insensitive fixed aliases only: `gc`, `cat`, `type` to `Get-Content`; `sls` to
  `Select-String`; `gci`, `ls`, `dir` to the restricted `Get-ChildItem`; `cp`, `copy`,
  `cpi` to restricted `Copy-Item`; `%`, `foreach` to restricted `ForEach-Object` in
  command position. Each mapping needs default-session evidence in both editions. Reject
  alias or function definitions, custom aliases, wildcard command names and unrecognized
  module-qualified names. No runtime `Get-Command` or profile inspection. Trusted
  built-in resolution and same-user command substitution are documented limits.
- Readers: `Get-Content` and aliases need explicit static file operands; `Select-String`
  needs static file operands and literal pattern data, with no implicit search. Prefer
  `-LiteralPath`; allow `-Path` or positionals only without wildcard or provider meaning.
  Every file operand goes through native validation and `paths.FileProtected`; protected
  stores, configured credentials, age-key and template namespaces and uncertain identity
  deny. Pattern and payload text are data, not paths. `-Wait`, byte/stream selectors and
  unmodeled parameter sets deny.
- Transfers and writes: `Copy-Item` accepts one certified public regular-file source and
  an explicit public non-directory destination, with no recursion, wildcards, links,
  remoting or containers. Every destination, redirect and writer path uses both
  `paths.FileProtected` and `paths.FileConfigWriteProtected`. `Set-Content` and
  `Add-Content` take literal `-Value` or certified inert pipeline data, not both;
  `Out-File` consumes only certified upstream data. No protected-write exception.
- Metadata: `Get-ChildItem -Name` is names-only on a certified explicit public directory,
  with no recursion, wildcards, custom formatting or provider enumeration. The initial
  native executable allowlist is empty: credential printers, provider CLIs, interpreters,
  `secret` operator/value commands and arbitrary executables deny. Fixed reasons and
  path-role semantics come from `internal/hook/roles/roles.go`, without inheriting
  Bash-specific consumer or credential-pipe exemptions.
- Pipelines are object pipelines: classify every stage and output stream; permit only
  documented compatible producer/consumer edges and reject implicit filename or property
  binding into readers or writers. Source states are literal data, certified public file
  content and unknown; unknown cannot certify an allow. `Out-Null`, filtering or
  redirection never erase an upstream denial.
- Redirects: allow static non-protected destinations for `>`, `>>`, the tested
  stream-number equivalents and tested merges such as `2>&1`, classifying every target
  before execution. Deny input redirection, dynamic targets, provider targets and
  unmodeled stream forms. Output encoding differences are no exemption.
- Nested blocks: only `ForEach-Object { ... }` with one static block of the same
  permitted statements, inspected recursively regardless of reachability. No `$_`,
  `$PSItem`, parameter blocks, member expressions, pipeline-supplied commands, parallel
  execution or state mutation. Standalone invocable blocks, functions, classes, loops,
  conditionals and traps deny initially.
- Always deny `Invoke-Expression`/`iex`; dot-sourcing; all `&` invocation; variable or
  subexpression command names; splatting; all here-strings; `Start-Process`, jobs,
  remoting, runspaces, reflection and module loading; `--%`, `--`, encoded source and
  nested `powershell`/`pwsh` launches including `-EncodedCommand` and abbreviations;
  CMD, batch, WSL and Bash passthrough. Deny `Env:`, `Cert:`, registry, `Variable:`,
  `Function:`, `Alias:`, custom PSDrives and provider-qualified paths. Paths are literal
  drive-absolute, UNC or correctly anchored relative paths only.
- Native path reuse is explicit: `internal/hook/paths/file.go`, `native_windows.go` and
  `native_writes_windows.go`. Preserve the union of lexical, legacy and native identity
  witnesses, including UNC/share/subst aliases, junctions, missing suffixes, configured
  credentials and Git HEAD signatures. Never route PowerShell through Bash
  `Metadata.Protected` alone or broaden shared Bash helpers. Deny ADS, devices,
  reserved or trimmed names, unresolved reparse or metadata errors, cwd mutation, drive
  creation and link creation.
- PowerShell operands are anchored, not expanded. `paths.FileResolve` delegates to
  `Resolve`, which expands Bash-style `~`, `$HOME` and XDG prefixes; in PowerShell a
  single-quoted `'$HOME/x'` names a literal relative directory `$HOME`. Decoded
  PowerShell file operands are joined to the validated cwd with native semantics and no
  prefix expansion before the existing protection helpers run, keeping every lexical,
  legacy and native witness. Initially deny file operands that start with `~` or `$` or
  contain `${`, rather than model tilde or provider expansion. Tests pair protected and
  public reads and writes for a literal dollar-named directory, a protected cwd, and
  HOME differing from USERPROFILE.

## Verification and evidence gate

- Adjacent table-driven tests pair public controls with protected reads and writes and
  cover aliases and case, exact binding, comments, quotes, escapes, malformed syntax,
  pipelines, every stream, static nested blocks, every prohibited construct, both host
  envelopes, wrong types and duplicates, invalid UTF-8 and surrogates, limits at and past
  boundaries, panic and injected deadline exhaustion. A synthetic corpus lives under
  `testdata/hook/powershell/`; the Windows `Bash` all-deny corpus and every Unix
  expectation stay.
- Native differential tests compare Go structure with an independently projected
  `ParseInput` AST: command identity and invocation operator, decoded literal bytes,
  spans, parameters, pipeline edges, redirect targets and streams, and nested blocks.
  Every Go-accepted case must parse without errors and match in both editions; any
  unsupported oracle node prevents acceptance. Conservative rejections carry named
  reasons. Synthetic sources only; nothing is executed. AST equivalence is a syntax
  claim only.
- Binding evidence is separate and independent. A test-only projection uses
  `[System.Management.Automation.Language.StaticParameterBinder]::BindCommand` on each
  oracle `CommandAst`, in fresh no-profile sessions of both pinned editions, plus
  built-in command metadata (`Get-Command` parameter sets, positions,
  `ValueFromPipeline` and `ValueFromPipelineByPropertyName`), and compares every bound
  parameter, positional assignment and pipeline-input contract with the Go role table.
  Cover positional, named and colon forms, quoted dash-prefixed data, `-Path` versus
  `-LiteralPath`, PSPath and property binding, and the `ForEach-Object` script-block
  parameter. Any binding exception, ambiguous or dynamic parameter, or unresolved
  pipeline binding prevents acceptance; Go denies the same shapes.
  [StaticParameterBinder](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.staticparameterbinder.bindcommand).
  [ParseInput API](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser.parseinput?view=powershellsdk-7.4.0).
- `FuzzPowerShellParse` and `FuzzPowerShellAnalyze` in `internal/hook/ps/` use bounded
  source and fake path callbacks, one target per invocation with
  `-fuzztime=15s -parallel=2`: no panic, bounded work, deterministic results and no
  allow after incomplete analysis. Crash-seed replay is not differential coverage: a
  bounded native generation pass on windows-latest produces grammar-directed mutations
  (argument-mode commas, quote adjacency, backticks, comment boundaries, stream-number
  adjacency, nested blocks), sends every Go-accepted input through both editions' AST
  and binding projections, and fails CI on any mismatch, persisting the minimized case
  into `testdata/hook/powershell/` for mandatory replay. Native
  path tests require public/protected junction, symlink, UNC and subst witnesses and
  report absent 8.3 support explicitly.
- Extend the inactive real-host harness, not its activation: Windows Claude PowerShell
  on 5.1 and pinned 7.x, Git Bash present and absent, retained Bash refusal, and Windows
  Codex dialect and workdir discovery. Require structured tool attempts, a healthy
  control, linked hook results and filesystem witnesses, and repeat missing launcher,
  bad image, exit failure, crash, forced termination, malformed or blocked output,
  timeout, valid deny and neutral controls. A skipped tool, refusal, authentication
  failure or missing witness is incomplete, not a pass.
- `tests/test-host-hooks.py` and `.github/workflows/host-hooks.yml` are Unix-oriented;
  add Windows process-tree watchdog and fault handling and disposable test-plugin setup
  without Unix signals, chmod or release-asset assumptions. Record sanitized versions,
  tool and field facts, cwd/workdir matches, revision, run URL and outcomes; never upload
  raw sessions or values.
- Real-host jobs stay manual, non-required and disabled pending sponsorship, explicit
  owner approval, protected `host-hook-tests` reviewers and trusted refs,
  `vars.SECRET_HOST_TESTS == 'enabled'`, owner-provisioned authentication and approved
  spend. Configuration lives only in disposable hosted roots; never install hooks on a
  developer machine. No Windows shell protection claim until all applicable real-host
  rows pass; parser CI can finish while M5e stays incomplete.
- Regression gate: formatting, build, vet, uncached and race tests on native OS jobs;
  cross-vet is supplemental. Keep every existing shell, provider, CLI and plugin gate,
  Bash 3.2, exact `tests/go-hook.sh` outcomes and `testdata/inventory/` bytes, with no
  PowerShell rows in the Bash divergence inventory. Measure Windows process-launch p99
  and worst-case timeout with a fresh binary; never enlarge deadlines to hide parser cost.

## Ordered commits and estimates

| Step | Commit subject and scope | Days |
| --- | --- | --- |
| 1 | `docs(hook): define powershell host and parser contract`: this plan, the `go-rewrite.md` section 9 revision, ROADMAP without ticks, host and 7.x pins and oracle expectations in `testdata/hook/powershell/`. | 1 |
| 2 | `fix(hook): recognize windows powershell calls and deny unknown contracts`: `hook.go`, `input/input.go`, `bash_windows.go`, new `powershell_windows.go`; tests for command typing, the Windows shell cap, host routing and default denial. Unix dispatch unchanged. | 1.5 |
| 3 | `feat(hook): classify powershell ast with safe-source and failure assertions`: `internal/hook/ps/{parse,policy,roles}.go` with non-expanding operand anchoring and `#requires` denial, table and fuzz tests, the corpus, test-only oracle `tests/powershell-ast.ps1`, pending adapter seam only, and `hook-tightening.md` entries. | 3.5 |
| 4 | `test(hook): gate powershell parsing against native editions`: `ci.yml`, `tests/test-powershell.ps1`, AST and static-binding differential runners requiring 5.1 and 7.x, the bounded differential generation pass, oracle fault tests, native alias and path controls and performance evidence; CONTRIBUTING commands. | 3.5 |
| 5 | `test(hook): expand real windows host dialect matrix`: inactive Windows extensions to `host-hooks.yml`, `test-host-hooks.py`, `host-hook-fixture.go`, `testdata/host-hooks/` and `host-failure-evidence.md`, with offline classifier and fault tests. Executes only after separate owner authorization. | 2 |
| 6 | `docs(windows): record powershell evidence and remaining gates`: `docs/windows.md`, SECURITY, CHANGELOG, ROADMAP and this plan. Only if sponsored host evidence passes, enable the evidenced routing entry with its tests; otherwise keep denial and pending boxes. | 1 |

Total: 12.5 engineering days within the 8 to 14 day budget (raised from 10.5 after plan
review added binding evidence, differential generation and operand anchoring); sponsorship wait and
blocked host execution are not engineering completion. Each behavioral commit carries
its tests. Re-estimate rather than weaken the grammar, failure gate or native tests.

## Risks, exclusions and owner decisions

- Risks: grammar and parameter-binding differences, mutable aliases and providers, host
  upgrades and wrapper preprocessing, unavailable effective cwd, native metadata latency
  and decision/execution races. The subset intentionally over-denies. Static analysis
  does not contain malicious commands, same-user substitution, transformed values,
  unobserved tools or later Codex `write_stdin`; this is accident prevention, not a
  sandbox. No credential stores or provider values are read.
- Out of scope: CMD or Bash-on-Windows analysis, arbitrary native commands or scripts,
  dynamic expressions, cross-session state, profile or module inspection, new secret
  transports, Windows releases or installers, manifest or default promotion, M4.1
  output changes and Unix PowerShell.
- Owner decisions required:
  1. Approve replacing the rewrite plan's runtime helper with the Go subset.
  2. Approve starting conditional M5e (steps 1 to 4 can finish without host evidence).
  3. Sponsorship, spend approval and protected Windows host sessions for step 5.
  4. Exact host-version updates if existing pins lack the documented PowerShell tool.
  5. Whether to sponsor eventual Codex support or leave that host explicitly denied.
  6. Whether a future installed-manifest change should add the `PowerShell` matcher
     (M4.1 scope), given the installed guard is not invoked for that tool today.
