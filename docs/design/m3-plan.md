# M3 operator workflow implementation plan

M3 adds consent-gated operations and names-only interfaces while preserving Bash compatibility, existing text
output and M2 hook policy. No CLI or plugin cutover, v2 migration or Windows support expansion happens here.
Drafted by gpt-planner, revised after a gpt-plan-reviewer pass, owner parameters decided 2026-10-15.

## Current boundaries

`cmd/secret/main.go` delegates to `internal/cli`; keep it unchanged. `internal/backend/backend.go` already has
exact-account Get/Put/Delete, but Stash overwrites accounts and cannot implement transactional rotation.
`internal/store/parse.go` copies values; metadata consumers need shared parsing without retained values. Both
existing guards deny unknown secret subcommands, including the new operators and diff/doctor/completion. Preserve
that behavior and document it rather than modifying M2 policy.

```text
Before: main -> cli -> store/backend -> values -> supervisor/redactor
After:  main -> cli -> consent -> operator -> locked store/backend
                    -> metadata -> JSON/completion/MCP
                    -> run -> anchored template -> supervisor/redactor
                              operator events -> opt-in audit
```

## Owner parameters (decided)

- **Lifecycle CLI:** positional `secret rotate REF KEY`, `secret delete REF KEY`, `secret rename REF OLD NEW`, with
  explicit label selectors and terminal confirmation. Values never appear in argv.
- **Templates:** literal `{{KEY}}` placeholders with no expression language; the child receives the rendered file
  path in `SECRET_TEMPLATE_FILE`. Missing or unselected keys are rejected.
- **MCP exposure:** off by default; a configured server serves only explicitly allowlisted stores and may show key
  names, labels, backend kind, store paths and provider account IDs. It never exposes values or mutation.

## Ordered work items

New implementation files and their adjacent tests land together. All fixtures, providers and terminals are
synthetic or disposable. "go matrix" means the existing Ubuntu, macOS and Windows vet, unit and race jobs; Windows
permission-dependent features reject before side effects until M5a.

### 1. Foundation and consent

Files: `internal/store/{parse.go,metadata.go,metadata_test.go}`, `internal/secure/{bytes.go,bytes_test.go}`,
`internal/cli/{operator.go,operator_test.go}`.

Share parser semantics with a metadata mode that retains no value bytes. Define byte ownership, fixed errors,
typed metadata, transaction and audit-event interfaces. Require stdin and stdout TTYs before store access and
controlling-terminal target and key confirmation for destructive or value-moving operations; no bypass flags,
piped confirmation or operator JSON.

Acceptance: labels, malformed assignments, duplicates, refusal-before-access spies, hidden input and cleanup.
CI: go matrix; Unix PTY confirmation in item 8.

### 2. Transactional mutations

Files: `internal/store/{mutate.go,mutate_test.go,manifest.go,manifest_test.go}`,
`internal/backend/{transaction.go,transaction_test.go}`.

Reuse WithWriteLock, anchored reads and atomicReplace. Add whole-manifest publication under the existing lock and
formatting-preserving file mutations. Prepare fresh accounts, verify bytes, publish, then garbage-collect exact
old accounts. Persist names-only recovery intent before provider mutation; never back up values, steal locks or
enumerate providers.

Acceptance: phase-by-phase fault injection, collisions, concurrent writers, killed-writer recovery and
unaffected-byte goldens; the previous manifest survives a pre-publication failure. CI: go matrix with Unix crash
and filesystem assertions; real destinations in item 8.

### 3. Keychain byte transport

Files: `internal/backend/{keychain.go,keychain_test.go}`.

Replace DecodeString and string conversions with byte hex decoding, validate UTF-8 by byte decoding, and replace
strings.Builder and hex strings with an owned byte command buffer. Clear normalized input, captured output,
decoded intermediates, the encoded command and readback buffers when ownership ends. Preserve `security -i` stdin,
`-g` parsing, limits, the exact keychain path and fixed errors.

Acceptance: unchanged wire bytes and argv, text and hex round trips, invalid UTF-8, control and oversize
failures, cleanup assertions. CI: go matrix and the disposable macOS keychain job.

### 4. Structured inventory and diff

Files: `internal/feature/{inventory.go,inventory_test.go}`, `testdata/feature/inventory.json`,
`internal/cli/show_compat_test.go`.

Typed versioned metadata for `list`/`show --format=json`, diff, completion and MCP. Diff reports keys, labels,
presence and backend, never value comparisons, hashes or lengths. The existing text `show` output stays as is,
including ordered duplicates, masks and byte lengths.

Acceptance: JSON goldens, selection and ambiguity tables, changed values producing identical metadata, zero
provider Get calls, exact legacy text goldens. CI: go matrix and the unchanged CLI parity suites.

### 5. Import/export, lifecycle and doctor

Files: `internal/feature/{importer.go,importer_test.go,operator.go,operator_test.go,doctor.go,doctor_test.go}`,
`testdata/feature/doctor.json`.

After 2, import dotenv, op and bw with bounded private byte parsing, fixed subprocess arguments, safe opaque item
references and explicit field mappings. Require explicit absolute `file:` references or implemented keystore
references. Export destinations are keychain or libsecret only, must differ from the source and require
`--on-conflict=fail`. Without selectors, export selects unlabeled records only. Dry-run reports names and
conflicts only. Validate references, mappings, selections and destination collisions before any value-provider
call, and recheck under the destination lock. Publish batches through item 2.

Rename, rotate and delete use exact identities and the consent boundary; rotation takes hidden terminal input.
Doctor emits versioned JSON for modes, aliases, hook activation and trust, checksums, config certification,
backend availability, compatibility and tracked orphan guidance. It represents unavailable or not-installed M4
artifacts explicitly, never invents verification and never fetches values by default.

Acceptance: invalid preflight makes zero value-provider calls; provider-output bounds, cancellation, argv and
stderr sentinels, recovery and doctor goldens. CI: go matrix with mocks; Ubuntu libsecret and macOS keychain
integration after 3.

### 6. Private templates

Files: `internal/feature/{template.go,template_test.go}`,
`internal/cli/{launch.go,launch_test.go,launch_unix.go,supervise_test.go,template_guard_test.go}`.

Render selected byte values under the fixed `HOME/.secrets/.rendered/<random>/payload`, independent of
`SECRETS_DIR`. Use anchored, symlink-resistant creation and identity validation; reject aliased ancestors and
insecure private namespace modes, and enforce 0700 directories and a 0600 payload. The existing ValidateDirectory
checks only the final component and is not enough. Reject exec and output-directory options; expose only
`SECRET_TEMPLATE_FILE` to the child. Keep all-loaded-value redaction.

Shut down the supervised process group explicitly before removing the payload on normal, error and
catchable-signal exits, including descendants that closed their pipes. Do not rely on the current direct-child
and filter completion.

Acceptance: modes, ancestor aliases, overrides, placeholder failures, spawn, filter and signal paths, pipe-closing
descendants and cleanup. Test leaked paths and aliases through both hook adapters while alive and after cleanup,
including concurrent access and every supported file, search and shell role. CI: Unix go jobs; Windows rejects
early. SIGKILL or power loss may leave protected plaintext: document this residual and never claim guaranteed
erasure.

### 7. Completion, audit and MCP

Files: `internal/feature/{completion.go,completion_test.go,audit.go,audit_test.go,mcp.go,mcp_test.go}`,
`testdata/feature/{audit.json,mcp.json}`.

After 4, completion consumes metadata only. Audit is off by default, writes bounded rotated 0600 names-only events
and offers versioned names-only JSON queries. An explicitly configured stdio MCP server exposes scoped
list/show/diff/health for allowlisted stores only, rejects value and mutation methods and bounds protocol input.

Acceptance: schema goldens, permission, symlink and rotation cases, query filtering, forbidden methods, allowlist
isolation, zero value fetches and no values, argv or provider stderr in records. CI: go matrix; Unix persistence
checks and Windows unsupported-persistence tests.

### 8. Coordinator integration and hosted gate

Files: `internal/cli/{cli.go,usage.go}`, `.github/workflows/ci.yml`, `tests/test-operator.py`,
`internal/backend/{operator_libsecret_test.go,operator_keychain_test.go}`, `ROADMAP.md`, `CHANGELOG.md`,
`CONTRIBUTING.md`, `docs/design/go-rewrite.md`.

Wire dispatch and audit events. Hosted Unix PTY tests run with `python3 -I` through consent, lifecycle, JSON, MCP
and template cleanup. Extend the isolated required-provider jobs, sampling argv without real credentials, and keep
every shell, Bash 3.2, inventory and exact hook gate. Add bounded feature fuzzing on Ubuntu. Local work is gofmt and
focused tests; milestone acceptance requires green applicable Actions jobs.

## Parallel ownership

After 1, independent agents own 2, 3, 4 and 6. After 2, item 5 proceeds against mocks; after 4, item 7 proceeds.
These file sets are disjoint. Interfaces are frozen in item 1; only the coordinator (item 8) touches shared
dispatch, workflow and documentation files.

## Fixed decisions and risks

ROADMAP fixes conservative M2 denial, a future verified Claude-only cutover, Codex keeping the Bash guard, no
Windows protection claim, audit off by default, MCP only when configured and names-only JSON allowed. Provider and
manifest publication is not jointly atomic, so doctor reports tracked candidates, not every historical orphan.
Go runtime copies and crash leftovers rule out secure-erasure claims.
