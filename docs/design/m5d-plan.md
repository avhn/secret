# M5d plan: opt-in age encrypted file stores

M5d adds encrypted-at-rest stores to the staged Go CLI without changing plaintext defaults, the
Bash CLI, installed hooks, plugin manifests or release identity. Owner approved starting M5d on
2026-10-25. Completion requires dependency review, ciphertext-only persistence, crash and
recovery evidence and green applicable hosted jobs. No release is authorized by this plan.

## Scope

- Non-goals: automatic migration, key generation or escrow, cloud key management, SSH, plugin or
  post-quantum recipients, passphrase encryption, Windows ACL work, rollback prevention, sender
  authentication, secure erasure guarantees and host fail-closed claims. Human-only get,
  clipboard consent and configured exec boundaries stay unchanged.
- M5d is independent of M4.1 and M5a. Linux and macOS enable filesystem operations; Windows
  compiles and tests the codec but rejects age filesystem operations before access until M5a
  provides private ACLs and handle-safe paths.
- All test identities are generated per test, never copied from a developer store.

## Architecture

`internal/store/parse.go` owns copied value bytes; `internal/store/manifest.go` implements
names-only v1 inventories; `internal/backend/backend.go` is an exact-account provider API, not a
whole-file transaction API, so age does not go through provider dispatch or one ciphertext per
account. `internal/store/write.go` provides the tokened `.write-lock`, marked private scratch,
anchored replacement and file fsync; `internal/store/mutate.go` supports in-memory mutation.
Reuse these, with a narrow anchored callback extension.

```text
Before: Go CLI -> plaintext parser / provider manifest -> byte values -> selection/redactor
After:  Go CLI -> explicit age:NAME -> bounded envelope metadata -> names-only features
                                  -> identity -> authenticated decrypt -> parser/selection/redactor
         consent -> age transaction -> existing anchored lock/scratch -> ciphertext-only rename
Default Bash CLI, plaintext discovery, providers and installed guards remain unchanged.
```

- `internal/backend/age.go`: age crypto, identity ownership and an age `store.Transaction`.
- `internal/store/age.go`: reference mapping, bounded envelope and metadata parsing, ciphertext
  persistence. `store` stays independent of `backend`.
- `internal/store/mutate.go`: a synchronous byte-batch helper returning owned bytes, preserving
  plaintext behavior.

## Dependency and cryptographic policy

- Use the `filippo.io/age` Go library (permitted for M5 by the rewrite plan), not the age
  executable: no PATH substitution, subprocess diagnostics, prompts or plugin execution, and full
  authentication before bytes are returned. Import only the core package.
- Before changing `go.mod`/`go.sum`, record one exact reviewed release, tag, module checksum, Go
  1.26.10 compatibility, dependency graph, licenses and govulncheck result. No `@latest`, cgo,
  toolchain upgrade or GPL/AGPL runtime dependency. Run `go mod verify`, tidy diff,
  `go list -m all` and the pinned govulncheck. A failed review blocks M5d; there is no CLI
  fallback.
- Native X25519 recipients only, one to 32 distinct; any matching identity decrypts. Reject
  duplicate, malformed, SSH, plugin and unknown recipients. Scrypt/passphrase mode is
  unsupported. Reject unsupported stanzas with bounded parsing before expensive work.
- Application-owned plaintext stays `[]byte` and is cleared on every path via
  `internal/secure/bytes.go`. Never format library errors or value-bearing structures.
  `ParseX25519Identity` takes a string with no wipe API; its copies are a documented best-effort
  cleanup limit, not a claim of key erasure.

### Dependency review (2026-10-25, step 2)

Reviewed `filippo.io/age v1.3.2`, tag `refs/tags/v1.3.2`, upstream commit
`b74dce4cdbe35b5e5f66c06d9612b72f89028758`. Downloaded with
`GOTOOLCHAIN=local GOFLAGS=-mod=mod`; Go 1.26.10 compiled a separate core-package
probe successfully. The dependency declares `go 1.25.0`; its advisory
`toolchain go1.27.0` does not change the main module toolchain. No cgo is used.
Only the core package is permitted, not the CLI, SSH, armor or plugins.

Verified module checksum records:

```text
filippo.io/age v1.3.2 h1:r6RSZLFSMm6rzKepZ7ZAYkKCu14f3/Me8c7uKYh7C8c=
filippo.io/age v1.3.2/go.mod h1:TH/Yr2sSRhCKbaH4XPxpUV0Us8Gv6txYUpiZQWz8Evk=
```

`go list -m all` graph delta against the pre-M5d module (a minus is replaced):

```text
+c2sp.org/CCTV/age v0.0.0-20260829155415-4448f2097b2d
+filippo.io/age v1.3.2
+filippo.io/edwards25519 v1.2.0
+filippo.io/hpke v0.4.0
+filippo.io/nistec v0.0.4
-github.com/rogpeppe/go-internal v1.15.0
+github.com/rogpeppe/go-internal v1.16.0
+golang.org/x/crypto v0.55.0
+golang.org/x/net v0.57.0
+golang.org/x/text v0.41.0
-golang.org/x/tools v0.38.0
+golang.org/x/tools v0.49.0
```

License review covered every added or upgraded module: age, edwards25519, hpke,
nistec, go-internal, x/crypto, x/net, x/text and x/tools each carry BSD-3-Clause
in their root `LICENSE`. CCTV/age offers 0BSD, CC0-1.0 or Unlicense in
`README.md`, License section; this review chooses 0BSD. No GPL/AGPL dependency
was found. CCTV, edwards25519, nistec, go-internal, x/net, x/text and x/tools
are graph/test dependencies, not imported production packages. The initial
isolated probe's lazy-loaded graph omitted x/net and x/text; final tidy/graph
comparison exposed them, and both additional root licenses were reviewed before
final acceptance. This is a review-timing deviation, not an unreviewed module
or a runtime import.

`go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...` on the original checkout:
`No vulnerabilities found.` The same pinned scan on the isolated core-package
probe: zero reachable or imported-package vulnerabilities, three module-only
advisories in x/crypto v0.55.0: GO-2026-6355 and GO-2026-6354 (SSH, fixed in
v0.56.0), and GO-2026-5932 (OpenPGP, no fix). Neither package is imported.
These are not reachable findings; any reachable finding in subsequent final
scans blocks this milestone. The exact pin intentionally precedes its first
codec import; tidy is checked again once that import lands. The final integrated
checkout scan with the same pinned command also reported zero reachable and
zero imported-package vulnerabilities, with only those three module-only
advisories. `go mod verify` reported `all modules verified`; the integrated
`go mod tidy -diff` was empty. Build, native vet and Windows/Darwin cross-vet
passed using Go 1.26.10 with `GOTOOLCHAIN=local`.

## References, identity files and permissions

- Explicit `age:NAME` resolution in `internal/store/resolve.go` maps only to
  `SECRETS_DIR/NAME.secret.age`. Default discovery and Bash `*.secret` discovery do not change.
  Reject age envelopes supplied as plaintext references; never treat corruption as an empty store.
- Require an explicit absolute `--age-identity FILE`, with no environment or default discovery.
  The file holds comments and up to 32 X25519 identities, capped at 64 KiB. Identity and
  recipient files live under the private `HOME/.secrets/.age-keys/` namespace (already
  protected by the hook path policy). Reject escapes, symlinked components, final symlinks,
  nonregular files and insecure ownership or modes. Never chmod existing files silently.
- Owner-only access: directories 0700, files 0600 or stricter. Anchored handles, no-follow final
  opens, bounded reads. Recipients are public but integrity-sensitive, so they are protected too.
  Namespace creation is explicit operator initialization.
- No identity material or path in the envelope, audit or MCP configuration; no cross-invocation
  cache; names-only operations never open identities. Missing or wrong identities and failed
  authentication return fixed errors without filenames, fingerprints or partial plaintext.

## Envelope version 1

- One file is the whole transaction. Framing: ASCII `secret-age-store-v1\n`, a big-endian u32
  metadata length, the metadata, then exactly one binary age stream to EOF. Caps: metadata
  1 MiB, file 18 MiB, decrypted payload 16 MiB, checked with overflow-safe arithmetic. Reject
  unknown versions, armor, truncation and trailing data.
- Metadata: u32 recipient count, sorted u32-length canonical X25519 recipient strings, then a
  u32-length canonical names-only `secret-manifest-v1\nbackend=age\n` inventory reusing manifest
  validation, capped at 1,024 key/label identities. Accounts stay stable across rotation, rekey
  and rename.
- Plaintext: ASCII `secret-age-payload-v1\n`, a SHA-256 binding of the exact outer prefix, length
  and metadata, then a u32 dotenv length and the dotenv bytes. The payload must be warning-free,
  duplicate-free and match the manifest exactly. Legacy plaintext parsing is unchanged.
- Read the whole age stream to authenticated EOF and verify binding, framing and manifest match
  before any selection, mutation or launch. Integrity detects corruption and substitution, not
  replay of an older valid envelope or authorship.
- Names-only show, JSON, diff, completion and MCP read bounded outer metadata without identity
  access; that metadata is unauthenticated and never authorization. Expose no ciphertext size,
  recipients, hashes or value lengths.

## CLI, operator integration and rekey

- New consent-gated commands, terminal-only with exact target confirmation and no `--yes`:
  `age-init age:NAME --age-recipients FILE --age-identity FILE` and
  `age-rekey age:NAME --age-identity FILE --age-recipients FILE --age-new-identity FILE`.
- `--age-identity FILE` only on value-consuming commands (stash, get, clip, run/exec,
  import/export, lifecycle). Writes keep recipients from the authenticated envelope; only rekey
  replaces them. Creation requires age-init. `list --backend age` is explicit age-only
  discovery.
- Import/export integrate age sources and initialized targets with insert-only conflicts and
  consent; plaintext export targets stay prohibited. Migration leaves the source untouched and
  claims no erasure.
- Rekey and init prove a supplied identity decrypts the complete candidate before publishing.
  Removed identities fail on the new file; old ciphertext copies stay readable with old keys.
- `run` loads every age record, including unselected values, into literal redaction and
  inherited-name removal; any authentication failure aborts before spawn. Age plus
  `--template-file` is rejected before decryption. Audit records only action, target and outcome.
  New operator commands stay human-only; hook denials are not relaxed.
- Files: `internal/cli/{cli,launch,features,operator,usage,age}.go`,
  `internal/feature/{inventory,operator,importer,completion,doctor,mcp,audit}.go`,
  `internal/store/metadata.go`, with adjacent tests.

## Binding review revisions

The plan review (2026-10-25) required these changes; they override earlier text:

1. Import keeps its existing source grammar and gains only initialized age destinations; age
   sources move through export (age to age or provider). Both commands reject every age to
   plaintext route before any value is fetched, with an explicit test for
   `import --from age:NAME --into file:...`.
2. Operator commands carry the confirmed exact source key and label identities into the
   authenticated read, recompute selection on that same authenticated snapshot, and abort on any
   selection drift before destination mutation. Values are never chosen from the unauthenticated
   preflight metadata. A deterministic concurrent source-change test covers it.
3. `age-init` is create-only: under the anchored write lock it rejects any existing target
   without decrypting or overwriting it. Rekey and ordinary writes reject a missing target.
   Tests cover an existing store and concurrent initializers (exactly one succeeds, existing
   bytes unchanged).
4. The reviewed `filippo.io/age` pin lands before the codec first imports it. Recipients are
   validated with `age.ParseX25519Recipient` and a canonical `String()` round trip, never a
   second hand-written decoder. Every ordered commit builds and passes its adjacent tests.

## Crash safety and recovery

- Extend `internal/store/write.go` with an anchored locked callback so the target directory
  cannot change between lock, read and rename; add an age-only strict directory sync. A
  post-rename fsync failure reports uncertain durability, never rollback.
- Under `.write-lock`: reread and authenticate, recheck identities and conflicts, mutate in
  memory, encrypt, fully verify the candidate, then write only ciphertext through private
  scratch, file sync and rename. No plaintext temp file, backup or journal.
- Failure before rename keeps the old file. SIGKILL leaves the tokened lock and maybe marked
  scratch: never steal, never roll forward; the human removes the stale lock and the next owner
  cleans marked scratch.

## Verification and CI

- Table tests in each package and `tests/test-age.py` for Unix PTYs and subprocess crashes.
  Recipient and identity matrix, rejected stanza types, names-only metadata, labels and
  selection, mixed plaintext/provider/age redaction, confirmation refusal before access,
  template rejection, alias and permission rejection, bounds, and on-disk plaintext scans after
  success and failure.
- Fault injection at encrypt close, candidate verify, scratch write, file sync, rename and
  directory sync; killed writers; concurrent writers and readers with no lost updates. Windows
  asserts filesystem rejection before opening paths; codec tests run on all three OSes.
- Fuzz: `FuzzAgeEnvelope` (`internal/store/age_test.go`), `FuzzAgeDecrypt` and `FuzzAgeKeyFiles`
  (`internal/backend/age_test.go`), seeded with runtime keys, bounded, X25519 only; corpus holds
  no private keys.
- CI: Go 1.26.10 with `GOTOOLCHAIN=local` on all three OSes; add `go mod verify`; keep tidy diff
  and govulncheck; Linux fuzz loops at `-fuzztime=15s -parallel=2`, one target per invocation;
  Unix age PTY and crash checks on Linux/macOS. Keep every existing gate.

## Ordered commits

1. `docs(age): define opt-in encrypted store contract`
2. `build(age): pin the reviewed filippo.io/age module` (go.mod/go.sum and the recorded
   dependency review in this plan)
3. `feat(store): add bounded age envelopes and anchored transactions`
4. `feat(backend): add opt-in age encryption and rekey`
5. `feat(cli): integrate consent-gated age store workflows` (with `tests/test-age.py`,
   `docs/age.md`, README, SECURITY, CHANGELOG)
6. `test(age): gate encrypted stores across the go matrix` (fuzz, CI, CONTRIBUTING, AGENTS,
   ROADMAP evidence)

## Risks and limits

Names, labels, recipients and approximate size stay visible; public-key encryption is not proof
of authorship or freshness. Writes are linear in store size (16 MiB cap). Go and age keep runtime
copies beyond application cleanup; swap, core dumps and malicious same-user processes are outside
the guarantee. Migration and rekey do not erase old files or backups. Windows filesystem support
waits for M5a.
