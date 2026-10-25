# M5c plan: registered, read-only 1Password backend

M5c adds opt-in Go reads of explicitly registered 1Password fields without exposing values in
provider argv, diagnostics, JSON or audit. `run` fetches every registered field in each requested
store before starting its child, including unselected and overridden records, and redacts all
loaded literals on both output streams. Owner approved starting M5c on 2026-10-25.

## Scope

- Non-goals: provider writes, plaintext export, item discovery, attachment or OTP retrieval,
  automatic signin, interactive unlock, a new redactor, Windows launch support, Bash changes,
  installed-hook activation, release publication and plugin manifest bumps. `exec` stays
  unfiltered and agent-denied; `get` stays terminal-only.
- Linux and macOS execution; Windows keeps parser and metadata tests and fixed unsupported
  execution until M5a.

## Current boundaries

- `internal/backend/backend.go` dispatches only Keychain and libsecret over service plus random
  account IDs; `internal/store/manifest.go` accepts only v1 with 32-hex accounts. A 1Password
  reference must not be squeezed into that ID or accepted by weakening v1 validation.
- `internal/cli/launch.go` already loads all manifest records before selection; `cli.go` fetches
  only the selected record for get and clip.
- Provider subprocesses are capped at 15 seconds, 1 MiB per stream and a 250 ms pipe drain. Unix
  process groups are not detached sessions, so piping stdin alone does not stop `/dev/tty`
  access.
- `internal/hook/roles/roles.go` already denies `op read` and revealing item-get forms. Keep
  those denials with no internal-provider exception.

```text
Before: v1 manifest -> random account -> Keychain/libsecret -> []byte -> existing run redactor
After:  v1 path unchanged
        explicit registration -> v2 names-only manifest -> bound random ID -> exact op reference
        detached, bounded op read stdout -> owned []byte -> all-record load -> existing run redactor
        names-only list/show/diff/MCP --------------------> manifest only, never op
        agent direct op read ----------------------------> existing hook deny
```

## Manifest coordination across M5

M5b (pass) and M5a (wincred) keep the v1 record grammar under per-backend suffixes outside Bash
`*.keys` discovery (`NAME.pass-keys`, `NAME.wincred-keys`). 1Password needs fields v1 cannot
carry, so M5c defines the shared `secret-manifest-v2` container, stored as
`SECRETS_DIR/NAME.onepassword-keys` (also outside Bash discovery):

```text
secret-manifest-v2
backend=onepassword
{"key":"API_KEY","labels":{},"id":"0123456789abcdef0123456789abcdef","provider":{"reference":"op://VAULT_ID/ITEM_ID/password","account_uuid":"ACCOUNT_ID","auth":"service-account"}}
```

LF-delimited headers, then one canonical JSON object per line with exactly `key`, `labels`,
`id` (stable random 32-lowercase-hex record ID) and `provider`. The header selects one strictly
typed provider schema, never an extension map; for onepassword exactly `reference`,
`account_uuid` and `auth`. Unsupported backends stay rejected. Document and record limits and
canonical serialization are frozen with tests. Metadata JSON projects only key, labels and the
random ID, keeping its version and the existing `account` meaning (never the 1Password account
UUID).

## Design

1. **Registration and schema.** `internal/store/manifest_v2.go` plus `onepassword:NAME` in
   `manifest.go` and `resolve.go`. Records hold key, canonical labels, a stable random 32-hex
   record ID and the exact secret reference, plus an explicit authentication mode and account
   UUID. Reject duplicate or unknown fields, trailing JSON, version or backend mismatch,
   duplicate identities, IDs or references, controls and oversize documents. Reuse private
   no-follow reads, the write lock and atomic replacement; never auto-migrate v1.
2. **Reference grammar.** Only `op://VAULT_ID/ITEM_ID/[SECTION_ID/]FIELD_ID` with immutable
   26-character vault and item IDs and a bounded ASCII field grammar. Reject titles, share links,
   dot segments, percent escapes, interpolation, queries, fragments and option-like input. Moved
   items fail; there is no search.
3. **Human setup.** `secret register onepassword:NAME KEY --reference op://... --account UUID
   --auth session|service-account [--label N=V]` in `internal/cli/register.go` and
   `internal/feature/register.go`, using the terminal and exact-confirmation machinery from
   `operator.go` and a names-only audit action. No provider call at registration. Existing
   identity or account changes fail instead of retargeting. `register` stays agent-denied.
4. **Bound inventory.** A manifest-bound opener in `backend.go` returns one validated snapshot and
   a provider whose `Get(service, recordID)` resolves only IDs in it, shared by selected reads and
   launch preparation. Names-only listing never builds an op transport.
5. **Exact command.** Absolute `op` resolved from PATH, no shell:
   `op read --no-newline op://...`, with `--account UUID` in session mode. Never `--out-file`,
   `--force` or whole-item JSON.
6. **Authentication.** The manifest stores account UUID and mode, never a token. Session mode
   requires the human to sign in outside `secret`; service-account mode uses only an inherited
   `OP_SERVICE_ACCOUNT_TOKEN`, never argv, and rejects conflicting session or Connect settings.
   Before reads, bounded `op whoami --format json` must match the manifest account; freeze the
   exact field and supported CLI v2 version from official docs. Never print or audit it.
7. **Noninteractive execution.** Per-call options in `backend.go` and `process_unix.go`: detached
   session, EOF stdin, no controlling terminal, existing tree cancellation and bounds;
   `OP_BIOMETRIC_UNLOCK_ENABLED=false`, `OP_DEBUG=false`, `OP_CACHE=false`; no signin, retries or
   unlock. A shared 60-second deadline per invocation plus the 15-second per-process cap; timeout
   or rate limit aborts before the child starts.
8. **Bytes and errors.** Accept stdout only after bounded success as owned `[]byte`; clear stderr
   and rejected output. Enforce existing NormalizeValue rules exactly (reject empty, NUL, CR, LF,
   edge whitespace). Fixed safe errors for every failure, never wrapped exec or provider text.
9. **Read-only before side effects.** A fixed read-only error from Put and Delete, preflighted in
   `backend.go`, `transaction.go`, `feature/operator.go`, `cli/cli.go` and `cli/features.go` so
   stash, import target, export and lifecycle fail before hidden input, source reads, provider
   calls, recovery intent or filesystem changes.
10. **Consumers.** Update `cli/cli.go`, `cli/launch.go` and
    `feature/{inventory,completion,mcp,doctor}.go` for explicit references and v2 discovery,
    keeping names-only and MCP shapes. Doctor checks executable presence only.
11. **Stub boundary.** `stub_secretstub.go` never turns onepassword into a writable provider.

## Binding review revisions

The plan review (2026-10-25) required these changes; they override earlier text:

1. Value bytes: reject CR, LF and NUL in raw provider stdout before normalization, require the
   normalized bytes to equal the original bytes, and document the surrounding-quote restriction.
   Clear both buffers. Terminal LF, repeated LF, surrounding quotes and exact-byte cases are
   tested in the backend commit. The legacy stash normalizer is unchanged.
2. Authentication: only service-account mode is in scope. Session mode is deferred because the
   `whoami` JSON schema is undocumented. Account verification uses the same resolved executable
   and frozen environment as reads, accepts one exact field proven from sanitized fixtures of a
   pinned CLI release (2.18.0 or later), and fails on missing or ambiguous identity. Connect
   configuration is rejected (it takes precedence over the service-account token).
3. Registration writes only `NAME.onepassword-keys`, which Bash discovery never reads, with a
   mixed-directory test proving unchanged Bash still lists file and v1 stores.
4. The v2 container contract above is frozen; future provider payloads are not implemented now.
5. Registration has its own exact challenge showing target, key, labels, reference, account
   UUID and auth mode, validated before rendering. `register` is added explicitly to the action
   and audit validators in `internal/store/metadata.go` and `internal/feature/audit.go` without
   widening writable-operator acceptance. Mismatched confirmation and nonterminal input are
   rejected before any filesystem access.
6. `internal/feature/importer.go` rejects a onepassword import target during request validation,
   before reading its source. The fixed read-only error survives operator error translation.
   Direct feature API tests assert that error, zero provider calls and no audit, recovery or lock
   debris. Metadata acceptance stays separate from writable-target acceptance.
7. Activation gate: a named licensing review and successful isolated real-provider evidence
   (owner-provisioned read-only service account, synthetic vault) are prerequisites for enabling
   default dispatch and for marking M5c done. Until then onepassword dispatch stays disabled
   (inactive scaffolding, reachable only in tests) and the ROADMAP records M5c as scaffolded,
   pending provider evidence.
8. Commit order: the schema commit is internal-only with parser and writer tests; transport
   lands with its fake-op, cancellation and byte-contract tests; registration, discovery, bound
   reads and read-only preflights activate together (still behind the step 7 gate) with consent,
   redaction and guard tests; the final commit adds CI and integration orchestration only.

## Fake-op contract

- Test-only `testdata/onepassword/fake-op.go`, built as `op` in a fresh disposable PATH
  directory with disposable HOME, `OP_CONFIG_DIR` and cache; inherited OP variables removed.
  Never reach a real `op`.
- Accepts only the frozen whoami and read argv for mapped account and reference tuples; anything
  else fails. Records metadata-only argv and call order and boolean terminal checks.
- Scenarios: exact stdout bytes, stderr sentinels, exit codes, EOF and TTY probes, stalls,
  oversized streams and pipe-holding descendants.

## Test matrix

| Area | Required cases |
| --- | --- |
| Manifest and registration | v1 goldens unchanged; v2 round trip; malformed, duplicate and unknown fields; invalid IDs; size limits; private modes; symlink rejection; concurrent registration; atomic failure; no op call; consent rejection. |
| Read and authentication | Exact argv; missing executable; unauthenticated; wrong account; conflicting modes; absent field; denied vault; revoked token; rate limit; partial stdout with failure; output caps; deadlines; no controlling TTY under a PTY parent. |
| Value contract | Exact bytes; rejected malformed values; no newline stripping; cleared buffers; errors free of sentinels. |
| Redaction and launch | All registered unselected values filtered on both streams; chunk boundaries; ambient key removal; a missing field or exhausted budget prevents the child; multi-store failure clears earlier values. |
| Unsupported writes | Put, Delete, stash, import, export, rotate, rename and delete all return the fixed error with zero op calls and no debris, including secretstub builds. |
| Metadata | list, show, diff, completion, doctor and MCP never run op or expose values; audit names-only. |
| Guard regression | Both adapters deny direct, wrapped and quoted `op read`, revealing item-get forms and agent registration (`internal/hook/policy/onepassword_test.go`). |

## CI and evidence

- `.github/workflows/ci.yml`: explicit fake-op coverage on native Ubuntu and macOS, including the
  PTY no-controlling-terminal case; keep every existing gate. No real op, account or network.
- `internal/backend/onepassword_integration_test.go` behind `SECRET_REQUIRE_ONEPASSWORD=1`,
  unset everywhere. When enabled, missing setup fails. Real enablement needs an owner-provisioned
  read-only service account and synthetic vault; no authenticated CI job now.
- Green hosted CI proves the fake-op contract and redaction, not real 1Password interoperability.
  `docs/design/go-rewrite.md` requires direct provider integration for optional providers, so
  record synthetic completion separately from the pending real-provider gate.

## Documentation and risks

Update ROADMAP, CHANGELOG, README, SECURITY, `docs/design/go-rewrite.md` and a new
`docs/onepassword.md`: Go-only registration, v2 incompatibility with Bash discovery, dedicated Go
`SECRETS_DIR`, authentication outside agents, account pinning, read-only errors, total timeout,
unfiltered exec, registered-fields-only coverage and pending real-provider evidence. Risks: CLI
schema drift, licensing, stale IDs, rate limits amplified by all-record reads, account confusion,
PATH trust, inherited service tokens visible to children, values changing between reads, and
best-effort zeroing.

## Ordered commits

1. `docs(onepassword): freeze read-only backend and manifest contract`
2. `feat(store): add internal names-only v2 manifest container`
3. `feat(backend): add bounded onepassword read transport behind a disabled gate`
4. `feat(cli): wire onepassword registration, discovery and read-only preflights`
5. `test(onepassword): add fake-op ci and disabled isolated integration gate`

Sources: official 1Password CLI reference for `read`, `item get`, secret-reference syntax,
environment variables and `whoami`. These establish command surfaces, not a tested version.
