# M5b plan: pass backend

M5b adds an optional Linux/macOS `pass:NAME` backend to the staged Go CLI, with stdin-only
writes, private exact-entry reads, names-only inventory and verified transactional publication.
Owner approved starting M5b on 2026-10-25. Completion requires native hosted provider evidence,
not local mocks alone.

## Current boundaries and non-goals

- `internal/backend/backend.go` owns `Provider.Get/Put/Delete`, bounded subprocess capture and
  dispatch; `internal/backend/transaction.go` prepares fresh accounts, verifies bytes, publishes
  once and tracks recovery. Legacy `Stash` overwrites an existing account and is not reused
  unchanged for pass.
- `internal/store/manifest.go` supports names-only v1 records; `internal/store/write.go` supplies
  the shared `.write-lock` and private atomic replacement; `internal/secure/bytes.go` supplies
  byte clearing and fixed errors. Reuse them.
- `compat/secret` recognizes only `keychain:NAME` and `libsecret:NAME`, and its default discovery
  rejects unknown backends in every `*.keys` file, so `backend=pass` in an ordinary `NAME.keys`
  would break the active Bash CLI.
- Non-goals: Bash CLI or guard edits, hook-policy changes, installed-default promotion, release
  or manifest bumps, Windows provider support, a linked GPG library, arbitrary pass-entry
  registration, provider enumeration, clipboard transport, automatic initialization, migration
  and key management.

```text
Before: Go CLI -> file / v1 NAME.keys -> libsecret or Keychain -> private bytes -> run/redactor
        Bash   -> file / v1 NAME.keys; no pass reference
After:  Go CLI -> pass:NAME -> v1 NAME.pass-keys -> exact pass entry -> private bytes -> run/redactor
        mutations -> shared .write-lock -> recovery intent -> fresh entry -> readback -> manifest -> cleanup
        Bash   -> unchanged file / NAME.keys discovery, ignoring NAME.pass-keys
```

## Design

1. **References and manifests.** `pass:NAME` uses the existing NAME grammar. Keep
   `secret-manifest-v1`, the three-field records and 32-hex accounts; add only the `pass` backend
   identifier, with no schema bump. The manifest lives at `SECRETS_DIR/NAME.pass-keys`, recovery
   at `NAME.pass-keys.recovery`; legacy `NAME.keys` paths stay byte-compatible. Centralize
   reference-to-manifest-path construction in `internal/store/manifest.go` and extend Go
   discovery to the new suffix. Other M5 providers whose records fit v1 should reuse this
   per-backend suffix pattern rather than a new schema version.
2. **Identity.** `Provider` is unchanged. Service and account map to `secret/NAME/ACCOUNT/value`
   in the selected password store (`secret/NAME/ACCOUNT/value.gpg`). Labels stay manifest-only.
   Resolve `PASSWORD_STORE_DIR` or the HOME default once per provider; require an initialized,
   private, non-aliased directory and validate managed descendants with anchored operations.
3. **Provider pin and exact commands.** Certify upstream pass 1.7.4 and reject other versions
   before value operations. Fixed argv, no shell: `pass insert --multiline -- ENTRY`,
   `pass show -- ENTRY`, `pass rm --force -- ENTRY`; never `--echo`, clipboard, QR or recursive
   removal. Capture and clear all provider output, including insertion prompts.
4. **Collision safety.** In 1.7.4, `yesno` succeeds immediately for non-TTY stdin, so omitting
   `--force` does not prevent overwrite. Before insertion, atomically create the fresh account
   directory through an anchored root; any existing directory, file, symlink, sibling ciphertext
   or unsafe ancestor is a conflict, with no insertion and no deletion. External direct pass
   writers are outside the concurrency guarantee.
5. **Writes and recovery.** Stash goes through `Transaction.Apply` with one put and a fresh
   account. Import and export keep insert-only collision checks; rotation needs an existing
   identity. Hold the secrets-directory lock from recheck through reservation, insertion, exact
   readback, publication and old-account cleanup. Persist recovery intent before provider
   mutation. Publication or cleanup failure leaves names-only recovery and blocks later mutation.
   Never delete a collided or foreign entry or steal a lock.
6. **Reads and value domain.** Before show or delete, the exact ciphertext must be a regular
   non-symlink file, so a missing entry never falls through to pass's directory listing. Reads
   return owned `[]byte`. Keep the existing value domain: nonempty, no NUL, CR or internal LF,
   no boundary whitespace or matching surrounding quotes. Stash strips its one terminal LF;
   readback must equal the normalized bytes. Multiline and binary entries reject. A 64 KiB value
   bound with tested edges.
7. **Subprocess and GPG failures.** Reuse the 15-second process-group deadline, 250 ms pipe wait
   and bounded capture, via an environment-aware runner variant that leaves libsecret and
   Keychain unchanged. An explicit reviewed environment keeps required paths and the chosen HOME
   and GNUPGHOME and drops shell startup and tracing variables, exported functions and GPG option
   or recipient overrides; umask 077; extensions disabled; batch/no-pinentry GPG options so
   locked keys fail fast. Every failure becomes a fixed value-free error.
8. **CLI and metadata.** Enable pass in stash, show, list, get, clip, run, exec and consent-gated
   import, export and lifecycle. `run` loads every registered account before launch and redacts
   all loaded literals on both streams; a missing account aborts. JSON, diff, completion, MCP and
   doctor are metadata only with zero Get calls. No guard exemption.

## Binding review revisions

The plan review (2026-10-25) required these changes; they override earlier text:

1. Cleanup verification: pass 1.7.4 `cmd_delete` ignores `rm` failure and exits 0, so Delete
   success is never inferred from exit status. After every delete, an anchored check must prove
   the exact ciphertext absent; a remaining file or an uncertain stat keeps recovery. Add a
   regression where rm fails but pass exits zero. Git add/commit outcomes are outside the
   transaction contract and are not claimed as detected.
2. GPG configuration isolation: the provider owns `PASSWORD_STORE_GPG_OPTS`, frozen to
   `--no-options --batch --no-tty --pinentry-mode error` plus a captured private status and log
   destination, so a `gpg.conf` `output` or `status-fd` cannot write plaintext to a file or
   contaminate the value stream. Synthetic `gpg.conf` output and status tests assert no
   plaintext artifact and no pinentry launch.
3. Signature policy: the environment contract is enumerated in code. A configured
   `PASSWORD_STORE_SIGNING_KEY` is preserved after validation as uppercase hex fingerprints,
   never dropped. Missing, invalid and valid `.gpg-id` signature cases are tested; missing or
   invalid signatures prevent encryption and publication.
4. Commit order: pass resolution and discovery stay inactive until CLI routing and dispatch are
   wired, and provider classification rejects any unavailable pass operation before the file
   fallback, so no commit can create a plaintext file named `pass:NAME`. Each
   behavior-changing commit carries its own focused table tests.
5. Collision rule: `exportPlan` compares centralized manifest paths, not bare names, so
   `libsecret:team` and `pass:team` may export in both directions while the real keychain and
   libsecret `NAME.keys` collision stays rejected. Test recovery lookup and same-name discovery.
   `docs/design/go-rewrite.md` records the shared per-backend suffix rule and reserves v2 for an
   actual record-schema change.
6. Provider pin: CI installs pass 1.7.4 from upstream commit
   `1078f2514d579178d5df7042c6a790e9c9b731ad`, with a checked-in expected archive SHA-256,
   through the upstream Makefile under a disposable prefix including its platform file. Ubuntu
   installs its listed apt prerequisites; macOS runs `brew install gnupg bash gnu-getopt` and
   selects tool prefix, Bash and Homebrew PATH explicitly. The driver verifies the staged pass
   path, version and Darwin platform behavior before creating test keys. Download and
   extraction directories are separate from driver scripts, and builds happen outside real HOME.

## Acceptance matrix

| Layer and runners | Required cases |
| --- | --- |
| Reference and manifest units, all three OSes | Name validation; backend mismatch; duplicates; malformed records; private modes and aliases; names-only recovery; same NAME in legacy and pass manifests; unchanged v1 goldens; Bash discovery ignores pass manifests, Go finds both. Windows rejects real pass operations before any subprocess. |
| Transport stub | Exact argv and stdin; no added LF; cleared buffers; output sentinels never escape; missing executable or GPG; wrong version; empty, truncated or oversize output; nonzero exit after partial output; timeouts and pipe-holding descendants; environment blocks tracing and option injection. Default builds ignore `SECRET_BACKEND_STUB_DIR`. |
| Byte table, stub and native | Text, UTF-8, invalid UTF-8, metacharacters, quotes and spaces round-trip; empty, NUL, CR, multiline, edge whitespace and surrounding quotes reject; one terminal LF normalizes once; 64 KiB passes and 64 KiB + 1 rejects. |
| Collision and fault table | Existing identity, label collisions, duplicate batch identity, retry exhaustion, pre-existing ciphertext, directory and symlink; faults at intent, reservation, encrypt, readback mismatch, publish, post-publish and cleanup with the right manifest per phase and blocked recovery. |
| Concurrency and crash | Concurrent stash and operator writers on one directory; no lost updates; same account from separate roots collides at reservation; killed writers leave the tokened lock unstolen and recovery intact. |
| CLI and features | All commands above; consent refusal before access; export requires `--on-conflict=fail`; run label selection, inherited-key stripping and two-stream redaction; metadata paths work without pass; audit names-only. |
| Native GPG and pass, Linux and macOS CI only | Throwaway key and store; write, read, delete and operator lifecycle; missing store, `.gpg-id`, recipient or secret key; locked key with no pinentry; corrupt ciphertext; permission failure; partial-write recovery; no raw or encoded values in sampled argv; private modes; cleanup of only test-owned agents and directories. |

## CI wiring

- A required `pass` matrix job on `ubuntu-latest` and `macos-latest` with Go 1.26.10 and
  `GOTOOLCHAIN=local`. Install GnuPG, Bash and GNU getopt; stage pass 1.7.4 from a reviewed
  immutable source and digest, not an unpinned package. Record GPG and Bash versions.
- `go build -o "$RUNNER_TEMP/secret" ./cmd/secret`, then
  `python3 -I tests/test-pass.py "$RUNNER_TEMP/secret"`. The driver creates private disposable
  HOME, GNUPGHOME, PASSWORD_STORE_DIR, SECRETS_DIR and temp roots first, generates a throwaway key
  in batch mode, initializes only that store and sets `SECRET_REQUIRE_PASS=1` only for isolated
  children. It runs `TestPassIntegration` and `TestOperatorPassIntegration`; when the gate is
  set, missing setup fails instead of skipping. Cleanup kills only the disposable agent.
- Add `go test -tags secretstub -count=1 ./internal/backend` and keep every existing gate. Never
  enable the gate locally.

## Risks

pass 1.7.4 is GPLv2+; it is invoked as an optional external executable only, never linked,
vendored or bundled. Provider writes and manifest publication are not jointly atomic;
interrupted encryption, Git callback errors, recipient changes, locked agents and failed cleanup
can leave tracked ciphertext or empty reservations. Same-user tampering, trusted provider
configuration, runtime copies and transformed child output stay outside the guarantee.

## Ordered commits

1. `docs(pass): freeze m5b transport and compatibility contract`
2. `feat(store): add inactive pass references and isolated manifest paths`
3. `feat(backend): add collision-safe pass transport and transactions`
4. `feat(cli): activate pass routing, discovery and operator flows`
5. `test(pass): add isolated native gpg and collision matrix`
6. `docs(pass): document staged support and provider recovery`

Sources: pass 1.7.4 `password-store.sh`, `pass.1` and `COPYING` at git.zx2c4.com.
