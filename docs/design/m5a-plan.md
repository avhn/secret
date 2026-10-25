# M5a plan: native Windows CLI and Credential Manager

M5a replaces Windows runtime rejection and Unix-mode assumptions with tested native CLI
execution, private persistence and exact Credential Manager access. Completion requires native
`windows-latest` evidence, not a successful cross-build. Owner approved starting M5a on
2026-10-25. This plan is not implementation or publication approval for any release.

## Goal, boundaries and assumptions

- Support Windows amd64 development builds, file stores, `wincred:NAME`, names-only inventory,
  hidden input, supervised `run` and unfiltered `exec` emulation. Extend existing operator,
  template and audit paths only together with their native permission, terminal and lifecycle
  tests.
- Preserve `bin/secret`, installed Bash guards, plugin manifests, Unix behavior and existing v1
  manifests. M5a is independent of the blocked M4.1 activation milestone.
- Non-goals: Windows release assets, Scoop, automatic installation, default promotion,
  PowerShell/CMD analysis, host fail-closed claims, clipboard parity and Windows arm64 runtime
  certification. Keep unsupported clipboard behavior explicit rather than invoking arbitrary PATH
  utilities on Windows.
- Owner policy remains binding: no Windows shell protection claim until its adapter and actual
  host evidence exist. M5a denies shell requests when its shim executes; it cannot protect a
  request when the host skips or fails to start that shim.
- Use Go 1.26.10 and `GOTOOLCHAIN=local`; `go.mod` already pins `golang.org/x/sys` and
  `golang.org/x/term`. No new runtime dependency or cgo requirement is planned.

```text
Before: Windows Go -> mode-only writes; run/exec rejected; v1 Unix providers
        Go hook -> shared Bash analysis; installed CLI/hooks -> unchanged Bash
After:  Windows Go -> handle-anchored private writes -> file / NAME.wincred-keys manifest
                     -> exact CredMan API -> owned bytes -> child environment
                     -> pre-enrolled kill-on-close Job -> filtered run output
        development shim -> native file/patch checks; shell -> fixed deny
        installed Bash defaults and Linux/macOS release pipeline -> unchanged
```

## Findings that determine the design

- `internal/store/write.go` already uses `os.Root`, exclusive directory locks, token ownership
  and atomic sibling replacement. `lockBusy` retries every Windows permission error; Windows
  directory sync is skipped. `internal/store/read_other.go` follows final links, and
  `internal/store/manifest.go` skips Windows permission checks while rejecting operator
  publication/recovery outright.
- `internal/cli/launch_windows.go` rejects launches. Filtering and supervision are combined in
  `internal/cli/launch_unix.go`; `internal/cli/launch.go` removes environment keys
  case-sensitively. `internal/cli/hidden_other.go` does not disable echo before the prompt;
  `internal/cli/operator.go` rejects Windows and opens `/dev/tty` elsewhere.
- `internal/backend/backend.go`, `internal/store/resolve.go`, manifest parsing and several
  CLI/feature metadata paths recognize only keychain/libsecret. `internal/hook/bash.go` analyzes
  Windows envelopes as Bash; `internal/hook/hook.go` uses `HOME`, unlike native
  `os.UserHomeDir` discovery, and `internal/cli/cli.go` reads only `HOME`.
- Windows exclusions also exist in `internal/store/mutate.go` and
  `internal/feature/{operator,template,audit,doctor}.go`. Removing only the launch rejection
  would not establish native CLI parity. `docs/install.md` also contains stale pre-publication
  M4 statements despite the recorded v0.2.3 release.

## Design

### 1. Private storage and Windows paths

- Add `internal/secure/files_windows.go` (`//go:build windows`) and `files_unix.go`
  (`//go:build !windows`): narrow handle-based private-create/check helpers shared by store,
  template and audit. Use `golang.org/x/sys/windows` to create protected owner-only DACLs for the
  current user SID, reject NULL/permissive DACLs and unexpected ownership, and inspect actual
  handles rather than Unix mode bits.
- Make private directories private at creation with security attributes; create secret-bearing
  files under verified private parents and verify their DACL before writing bytes. Protect locks,
  tokens, scratch, replacement files, manifests, recovery, rendered payloads and audit files. Do
  not repair arbitrary parent directories or silently accept ACL-incapable filesystems.
- Update `internal/store/{write,manifest,mutate}.go`; add
  `internal/store/{read_windows,write_windows,write_unix}.go`, excluding Windows from
  `read_other.go`. Retain `os.Root` anchoring and lock identity. Native no-follow opens reject
  unsupported reparse points and verify final file identity; never replace anchored operations
  with check-then-use absolute path operations.
- Verify `os.Root.Rename` replacement semantics on the pinned toolchain. Use a handle-relative
  replacement where required, with flushed data, no delete-then-rename window and no copy
  fallback. Bound sharing/delete-pending retries; permanent access denial stays a fixed failure.
  Preserve the old destination on failed publication and document the absence of a power-loss
  durability guarantee where directory flushing is unavailable.
- Preserve `.write-lock` timeout, token-checked cleanup and manual stale-lock removal. A killed
  writer never authorizes automatic stealing. Test the permission-contention workaround against
  real delete-pending and permanent ACL-denied cases.
- Update `internal/store/resolve.go` and add `internal/secure/path_windows.go`: recognize native
  separators, drive-absolute and UNC paths; reject `C:relative`, volume-less rooted ambiguity,
  device namespaces and stream names for stores. Resolve identities from opened handles with
  `GetFinalPathNameByHandle`; retain lexical protection and missing suffixes. Do not collapse
  `link/..` before physical traversal.

Age filesystem operations remain explicitly unsupported on Windows in this stack;
private ACL foundations do not implement its strict directory-durability contract.
The pass transport and 1Password registration/value transport also retain their
Windows rejections. Names-only v1 and v2 reads use the native private-file boundary,
and their Windows test fixtures must carry protected DACLs rather than mode bits alone.

### 2. Credential Manager and manifest compatibility

- Add `internal/backend/wincred_windows.go` and `wincred_other.go`. Reuse
  `Provider.Get/Put/Delete`; bind `CredWriteW`, `CredReadW`, `CredDeleteW` and `CredFree`
  through reviewed native declarations where x/sys lacks wrappers. No `cmdkey`, PowerShell,
  external process or provider enumeration.
- Generic credentials with target `secret/NAME/ACCOUNT`, validated service/name grammar and
  32-hex account IDs; local-machine persistence for the current user, not enterprise roaming.
  Store raw blob bytes, enforce the native blob limit before calling the API, verify returned
  type/target and blob bounds, copy into owned `[]byte`, clear native blob memory before
  `CredFree`, keep failures fixed and value-free.
- Keep the v1 record grammar for wincred and store its manifest at `SECRETS_DIR/NAME.wincred-keys`
  (recovery `NAME.wincred-keys.recovery`), outside Bash `*.keys` discovery, following the M5b
  per-backend suffix pattern. Keychain/libsecret `NAME.keys` bytes stay unchanged. A
  mixed-directory test proves unchanged Bash still discovers file and v1 stores after a wincred
  manifest exists.
- Update `internal/backend/backend.go`, `internal/cli/{cli,usage,features,operator}.go` and
  `internal/feature/{inventory,operator,completion,doctor}.go` to share the reference/version
  rules. Metadata operations never fetch credentials. Non-Windows dispatch returns unsupported,
  not a file fallback.
- Reuse locked put/readback/publication and operator recovery intent. Fetch only registered exact
  targets, load every registered value before `run`, and abort before launch if any fetch fails.
  Clear buffers on every exit. Provider success plus manifest failure stays a names-only recovery
  condition, never orphan discovery or blind deletion.

### 3. Child execution, terminals and existing features

- Extract the bounded two-stream filtering loop from `launch_unix.go` into
  `internal/cli/launch_supervise.go`; keep `internal/transport/redact.go`. Windows lifecycle in
  `launch_windows.go`: a non-inheritable Job with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, no
  breakaway, enrollment atomic with process creation through `PROC_THREAD_ATTRIBUTE_JOB_LIST`
  and restricted inherited handles. No create-suspended fallback (a parent killed before
  assignment leaves an unenrolled child); unsupported means fail before launch.
- Fail before execution if Job setup fails, including incompatible enclosing jobs. Limit
  inherited handles to stdio. On filter/write failure, console cancellation, drain timeout and
  normal completion, terminate remaining Job members, wait boundedly and close handles before
  template cleanup. Never emit raw fallback output.
- `launch.go`: Windows case-insensitive environment removal, collision rejection and template
  variable replacement, without changing Unix matching. Resolve PATH/PATHEXT from the child
  environment; Windows argv quoting without an implicit shell. `exec` is supervised, unfiltered
  child execution, not process replacement.
- Add `internal/cli/{hidden_windows,operator_windows,operator_unix}.go`: disable echo before the
  prompt, use `CONIN$`/`CONOUT$` with verified console handles, preserve consent and terminal
  gates, restore console state on all catchable exits, reject redirected confirmation before any
  store/provider access.
- Apply the private helpers to `internal/feature/{template,audit,operator,doctor}.go` and
  `internal/store/{mutate,manifest}.go` before lifting their Windows guards. Importer children in
  `internal/feature/importer_process_windows.go` get the same bounded Job cleanup.

### 4. File/patch hooks and development shim

- Split `internal/hook/bash.go` behind `!windows`; add `bash_windows.go` returning a fixed denial
  for string and argv shell requests, never parsing them as Bash. Retain malformed-envelope
  denial.
- Update `internal/hook/{hook.go,paths/paths.go,paths/streams.go,patch/patch.go}` and add
  `paths/native_windows.go` for native home/path handling, case/volume aliases, reparse targets
  and ambiguous-path denial. Extend file-tool and apply_patch tests with public controls and
  protected aliases.
- Add a development-only `hooks/guard-go.cmd` that invokes a fixed sibling development
  `secret.exe`, never PATH or command text, and emits a fixed denial when the binary is missing.
  It is not referenced from installed manifests and is not a verified release launcher.

## Binding review revisions

The plan review (2026-10-25) required these changes; they override earlier text:

1. Reject, before any child is created and with a fixed error, exported values that cannot
   round-trip through the Windows UTF-16 environment (for example invalid UTF-8), because the
   child would print bytes the literal redactor does not match. Unix byte behavior and raw
   CredMan storage are unchanged. Tests for file and CredMan sources assert that no child starts.
2. Job enrollment uses `PROC_THREAD_ATTRIBUTE_JOB_LIST` only (native process creation, since Go
   `SysProcAttr` has no job list), for run, exec and importer children. Deterministic
   parent-death tests at the creation and enrollment boundaries.
3. Path traversal is platform-specific: Unix keeps physical `link/..` traversal; Windows matches
   native Win32 and `os.Root` lexical cleaning and derives physical identity from opened handles,
   keeping conservative lexical witnesses separately. A junction-plus-parent case is checked
   against a real native open.
4. CLI initialization, not only the hook, uses native Windows home discovery (USERPROFILE when
   HOME is unset), preserving explicit SECRETS_DIR and SECRETS_ENV. A subprocess test runs with
   HOME unset.
5. `internal/backend/transaction.go` also rejects Windows; lift it in the operator step after
   manifest and recovery prerequisites work, with success and injected-failure wincred
   lifecycle tests through the real transaction path.
6. Mandatory directory-sync call sites (`store/manifest.go` recovery, Publish and ClearRecovery;
   `feature/audit.go`) follow a platform durability policy: data flushes and real publication
   errors stay required; the Windows directory-durability limit is documented so successful
   transactions do not stay in recovery.
7. wincred manifests use the `NAME.wincred-keys` suffix (see design section 2), not v2 in
   `NAME.keys`.

## Steps 3 and 4 implementation status

The names-only v1 wincred manifest/recovery path and exact native transport are
implemented, not runtime-certified. Reference-to-path construction is centralized
in store.ManifestPath; NAME.wincred-keys never enters the Bash *.keys glob.
Metadata interfaces work without native provider access, including on Unix;
credential dispatch outside Windows returns unsupported. The step 3 split must
retain Locator's explicit wincred rejection until step 4 wires every provider
consumer, so no intermediate revision treats wincred:NAME as a plaintext file.

CredMan uses raw blobs with a 2560-byte bound and generic exact targets only.
API-owned read buffers are cleared before CredFree; write copies are cleared
without changing caller buffers. Portable injected API tests cover failure and
identity checks. The Windows-only required-provider tests use random synthetic
services, probe absence before writes, flush exact targets to a names-only journal
and register cleanup before writes. CI independently replays that journal under
always() and verifies absence, never enumerating or wildcard-deleting records.
No real provider access runs when SECRET_REQUIRE_WINCRED is unset. Hosted results
remain required; cross-vet and test compilation are not native evidence.

Windows operator/Transaction, launch, template and audit persistence guards remain.
Step 6 still owns transaction success/failure and recovery lifecycle coverage on
native Windows before lifting its guard. Steps 5-8 are not implemented by this
transport change.

## Native verification matrix and CI

| Required Windows lane | Evidence and failure assertions |
| --- | --- |
| Filesystem and ACL | Owner SID and protected DACL on every private object; reject broad inheritance and NULL DACL; concurrent writers, pending deletion, locked destination, crash and manual recovery, no torn replacement or leaked scratch. |
| Paths and hooks | Local drive and loopback UNC share; junctions and symlinks, mixed case and separators, 8.3 aliases where supported, link/parent traversal, drive-relative, device and ADS rejection; both host envelopes and patch moves. Required UNC/junction/symlink cases cannot silently skip. |
| Lifecycle and console | Native fixture spawning descendants and holding pipes; parent death, nested Job failure, cancellation, stalls, nonzero exit, handle leaks, template cleanup. Console/ConPTY harness for hidden paste, cancellation, restoration and piped-consent rejection. |
| CredMan and CLI | Synthetic blobs at size boundaries, exact target/type/readback, adjacent-target isolation, missing records, labels, filtering, operator recovery and delete; names-only JSON/audit/MCP, no sentinels in argv, diagnostics or filtered streams. |
| Shim, not host protection | Binary and shim under cmd/pwsh from paths with spaces; fixed shell denial, file/patch decisions, missing binary and output failure. Host-skipped hooks remain unproven and potentially fail-open. |

- Extend `.github/workflows/ci.yml` `go (windows-latest)` with native build and integration steps
  (PowerShell where native paths matter), `GOTOOLCHAIN=local`, disposable HOME/USERPROFILE/store
  roots and explicit exit checks. Record runner image, OS, architecture and toolchain; keep every
  existing gate.
- Add `internal/backend/wincred_windows_test.go`, platform tests and `tests/test-windows.ps1` with
  fixtures under `testdata/windows/`. Real CredMan calls only with `SECRET_REQUIRE_WINCRED=1` on
  hosted Windows CI; unset means no provider access; enabled means missing coverage fails. Unit
  tests use injected native API fakes.
- Unique service prefix per invocation (run/job identity plus randomness). Record exact targets
  before writes, register cleanup before each API call, plus an `always()` CI cleanup that
  deletes only recorded targets and verifies absence. Never enumerate or wildcard-delete
  credentials. Cleanup failure fails the lane.
- Cross-vet proves compilation only, not DACLs, UNC/reparse behavior, atomic replacement, console
  hiding, Job containment, CredMan availability or host enforcement. M5a completes only with
  linked green hosted runs and no skipped mandatory cases.

## Documentation, risks and ordered commits

- Update ROADMAP, CHANGELOG, AGENTS, SECURITY, README, CONTRIBUTING, `docs/install.md`,
  `docs/release.md` and `docs/design/{go-rewrite,hook-tightening,host-failure-evidence}.md` with
  the support table, gated commands, wincred manifest suffix compatibility, exec/ACL/durability limits and fail-open
  hosts. Correct stale M4 install status from existing release evidence.
- Risks: privilege-dependent UNC/symlink fixtures, inherited ACLs, reparse/rename races, Job and
  console timing, case-insensitive environment collisions, non-cancellable provider calls,
  native buffer ownership and provider/manifest partial failure. Do not promise secure erasure,
  same-user isolation or cancellation the native API cannot provide. Re-estimate rather than drop
  tests.
- Ordered signed commits, each with focused synthetic tests:
  1. `docs(windows): define m5a runtime and evidence contract`
  2. `feat(windows): add private handle-based storage and native paths`
  3. `feat(store): add inactive wincred manifest paths`
  4. `feat(backend): add exact credential manager transport`
  5. `feat(cli): supervise windows children with kill-on-close jobs`
  6. `feat(cli): add native console and private operator workflows`
  7. `feat(hook): guard windows file tools and deny shell calls`
  8. `test(windows): require isolated native cli and credman evidence`
  9. `docs(windows): record supported behavior and hosted gate evidence`
- Windows release assets and Scoop remain a separate owner-approved effort with an
  M4-equivalent provenance gate. Real Windows model-host sessions stay disabled unless sponsored
  and approved.
