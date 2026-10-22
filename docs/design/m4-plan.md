# M4 plan: releasable Linux/macOS core

M4 prepares digest-pinned, provenance-verified Linux/macOS binaries, verified opt-in launchers and an inactive host-test harness. Items 1-5 and 7 are M4 scope. Item 6 moves entirely to M4.1, Host evidence and Claude cutover. M4 does not change what main installs. Publication and later installed-default promotion require separate explicit owner approval.

## Current boundaries and assumptions

- `bin/secret` is Bash. Both Claude entries in `hooks/hooks.json` call Bash with timeout 5 and no `onFailure`. All four marketplace and plugin versions are 0.1.0. The Codex plugin and manual configurations point to `hooks/guard-secrets`.
- `cmd/secret/main.go` already supports `-X main.version`; leave it unchanged.
- `internal/hook/hook.go` returns successful empty output on safe requests, and `internal/feature/doctor.go` describes M4 as unavailable. Doctor needs accurate staged-release reporting in M4; the hook output contract is M4.1 work. Packaging alone does not prove protection.
- M3 is merged with every applicable hosted gate green. Tests use the actual `SECRET_CLI` override, not the older `SECRET_TEST_CLI` spelling in the rewrite design.
- CI runs on `main` pushes and PRs only, so candidate branches need PR or explicit `workflow_dispatch` coverage.

```text
Before: CLI symlink -> Bash CLI; Claude/Codex -> Bash guard; Go -> staged tests
M4:     Default CLI and Claude/Codex -> unchanged Bash; opt-in secret-go -> Go CLI
        Release S -> checksum C -> final tag C; host harness inactive
M4.1:   CLI symlink -> verified launcher -> Go CLI; rollback -> compat/secret
        Claude -> guard-go -> Go hook after real host evidence; Codex -> Bash
```

## Owner parameters

- Release version V = 0.2.2 (replacement identity approved by owner, 2026-10-22; see [release history](../release.md)). Tag `v0.2.2`; assets `secret-v0.2.2-<os>-<arch>`.
- Real Claude Code and Codex host sessions (owner decision, 2026-10-19): write the host-test harness and workflow, but keep it inactive until sponsors fund the model usage. `host-hooks.yml` is `workflow_dispatch` only and its jobs are disabled by an explicit repository variable check (`vars.SECRET_HOST_TESTS == 'enabled'`); it is never a required check and never runs on push or pull_request. Secrets are referenced by name only; values are never requested in chat.
- Consequence for the gate: M4 completes as the reproducible, attested Linux/macOS release with verified launchers and the hosted install matrix. The Claude Code cutover (activating `guard-go` with `onFailure: "block"` as the installed default) depends on host evidence under the owner decisions, so all activation changes are deferred, not staged in M4, until the harness runs green. It moves to a follow-up milestone, M4.1 (host evidence and Claude cutover). Until then the installed Claude hook stays on the Bash guard.
- Claude Code pinned at 2.1.295 initially and a concrete Codex package version before implementation tests. Later host upgrades rerun this gate.

## Fixed decisions

- Only linux/darwin amd64/arm64 assets. Windows keeps its development CI, with no release or protection claim.
- Codex stays on Bash. The installed Bash CLI stays default until approved promotion. No automatic Bash fallback.
- Audit stays off, MCP opt-in, M2 policy unchanged except explicitly reviewed output-contract work.
- All builds, installation and host-failure experiments run on GitHub-hosted runners with disposable HOME and synthetic fixtures, never by installing hooks on a developer machine.
- Retained shell is Bash 3.2-compatible; launchers are POSIX sh. Values never enter argv or logs. Downloaded files each get fresh empty directories; test scripts live elsewhere and Python uses `-I`.
- Signed lowercase conventional commits, no co-author trailers, emojis or em/en dashes. Branch pushes use `git-safe-push`; fast-forwards use `git-merge-safe`.
- Repository changes are reviewable and reversible. Each of these **requires explicit owner go-ahead**: pushing a release tag, creating or publishing a GitHub Release, promoting published manifests on `main`, changing the default branch, publishing external package metadata.

## Frozen release interface (item 1, coordinator, 2026-10-19)

Workers A to D build against this contract; changing it needs a coordinator edit here first.

- Version: `V=0.2.2`, tag `v0.2.2`. Toolchain: Go 1.26.10 (`go.mod` directive), `GOTOOLCHAIN=local`.
- Assets (raw executables, no archives): `secret-v0.2.2-linux-amd64`, `secret-v0.2.2-linux-arm64`, `secret-v0.2.2-darwin-amd64`, `secret-v0.2.2-darwin-arm64`.
- Build environment: `CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0 GOFLAGS= GOTOOLCHAIN=local SOURCE_DATE_EPOCH=$(git show -s --format=%ct S)`; flags exactly `-trimpath -buildvcs=false -ldflags="-buildid= -s -w -X main.version=0.2.2"`, package `./cmd/secret`. `scripts/build-release.sh OUTDIR` builds all four into `OUTDIR` and writes `OUTDIR/checksums-v0.2.2.txt`.
- Checksum grammar: exactly four lines, LF-terminated, sorted by asset name, each `<64 lowercase hex sha256><two spaces><asset name>` (GNU `sha256sum` and `shasum -a 256` format). No blank lines, comments, duplicates, paths or other names; any deviation rejects the whole file. The committed copy lives at `dist/checksums-v0.2.2.txt` (introduced only by checksum commit C).
- Platform mapping: `uname -s` `Linux`/`Darwin` to `linux`/`darwin`; `uname -m` `x86_64`/`amd64` to `amd64`, `aarch64`/`arm64` to `arm64`. Anything else is unsupported and denies.
- Cache: `${XDG_CACHE_HOME:-$HOME/.cache}/secret/v0.2.2/` (directory mode 0700, owned by the user, no symlinked components below `$HOME`). Verified binary at `<cache>/secret` (mode 0500) and names-only metadata at `<cache>/verified` (lines `version=`, `asset=`, `sha256=`, `commit=`, `tag=`); installer lock at `<cache>.lock` (a directory created with `mkdir`, containing `owner` with pid and a random token). Launchers rehash `<cache>/secret` against the committed checksum line for their platform before every exec.
- Installer: `scripts/install-release.sh [--from-dir DIR] [--offline]` run from a trusted checkout. Default mode downloads `https://github.com/avhn/secret/releases/download/v0.2.2/<asset>` and verifies with `gh attestation verify` as in item 2; `--from-dir DIR` installs from already-downloaded assets plus `gh attestation download` bundles in `DIR`, still verifying digest and attestation; `--offline` forbids network and fails if verification needs it. Exit 0 installed or already current, 1 verification failure, 2 usage, 3 lock timeout, 4 unsupported platform or missing dependency. Never prints file contents or values.
- Test-only fixture mode: tests may run launchers and the installer against a disposable checkout whose `dist/checksums-v0.2.2.txt` is a candidate manifest, with `--from-dir` assets and a test-only `SECRET_RELEASE_TEST_ROOT` pointing at a disposable cache root and skipping attestation **only** when the checkout also contains the file `.secret-release-test-fixture`, which no shipped commit may contain (CI asserts its absence in S and C).
- Claude hook launcher: `hooks/guard-go` (POSIX sh). On any bootstrap failure it prints exactly one line and exits 0:
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"secret: verified binary unavailable; run scripts/install-release.sh"}}`
  If that write fails it exits 2 with fixed stderr `secret: verified binary unavailable`. On success it `exec`s `<cache>/secret hook claude` with stdin untouched.
- CLI launcher: `bin/secret-go` (POSIX sh, later staged as `bin/secret`). On bootstrap failure it prints `secret: verified binary unavailable; run scripts/install-release.sh` to stderr and exits 70; otherwise `exec <cache>/secret "$@"`. No Bash fallback in either launcher.

Launcher regression tests retain caller Go module/build caches before changing HOME and repair permissions only in owned disposable scratch during cleanup. Overlong symlink tests accept Darwin's kernel ELOOP rejection while independently exercising the launcher's 32-link bound with the chain supplied as shell `$0`. Closed-stdout tests require exact fixed stderr under the native sh and available dash/Bash POSIX interpreters. Offline fixture tests pass physical cwd paths and distinguish aliases from genuinely different directories; none of these synthetic checks proves installed-host protection.

## Ordered work items and parallel ownership

### 1. Freeze the release interface (coordinator, before parallel work)

Files: `docs/design/m4-plan.md`, `docs/design/go-rewrite.md`.

Freeze four raw executable asset names `secret-v<V>-<os>-<arch>`, checksum grammar, exact V, Go 1.26.10, source epoch, cache layout, installer arguments and failure JSON. Raw binaries avoid archive timestamp and order variability.

`scripts/install-release.sh` performs explicit preinstallation and provenance verification. Launchers consume its private cache and may attempt only bounded bootstrap. Full network verification must not consume the five-second hook budget: a cold hook may deny with fixed preinstall guidance and must never relax validation to succeed. Candidate fixture injection exists only in disposable test checkouts, never as a production trust-bypass variable.

Acceptance: architecture and release identity tables, malformed or duplicate checksum rejection, and the test-harness contract are agreed before workers edit their disjoint files. Record the candidate-workflow versus final-tag provenance distinction.

### 2. Deterministic builds and provenance (worker A, after 1)

Files: `.github/workflows/release.yml`, `scripts/build-release.sh`, `scripts/verify-release.sh`, `tests/test-release.py`. Jobs: `release-build-a`, `release-build-b`, `release-repro`, `release-attest`, `release-verify`, `release-publish`, plus the read-only
`release-rehearsal` PR/manual job described in [release.md](../release.md).

Build twice on independent fresh hosted jobs with different absolute checkout and build directories, separate caches, exact toolchain and dependencies:

```sh
CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" SOURCE_DATE_EPOCH="$epoch" \
  go build -trimpath -buildvcs=false -ldflags="-buildid= -s -w -X main.version=$V" -o "$out" ./cmd/secret
```

Freeze `GOAMD64`, `GOARM64` and `GOFLAGS`; embed neither HEAD nor wall-clock time. The epoch is `git show -s --format=%ct S`, reused at C.

`release-repro` runs `cmp` on all four assets plus a sorted SHA-256 manifest comparison, for every candidate and the final tag. Only `dist/checksums-v<V>.txt` may change between S and C; any other change (workflow, docs, plugin versions, source) fails.

At final tag C, attest rebuilt assets and the checksum asset with `actions/attest-build-provenance` pinned to a reviewed SHA. Scope `contents: read` globally, `id-token: write` and `attestations: write` to attestation, `contents: write` only to approved release jobs; never run untrusted fork code with credentials.

Verify every asset:

```sh
gh attestation verify "$asset" --repo avhn/secret \
  --source-digest "$C" --signer-digest "$C" --source-ref "refs/tags/v$V" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --cert-identity "https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v$V" \
  --deny-self-hosted-runners --format json
```

After checkout, restore the remote annotated tag into the local ref before any tag-type or peel checks, including script calls. Require the peeled commit to equal `GITHUB_SHA`; published-mode installation jobs repeat this restoration.

Check subject name and digest against local SHA-256 and the committed manifest, certificate and workflow identity, and peeled tag equality to full C. Never substitute candidate S provenance.

Acceptance: byte equality; a changed binary, repo, workflow, source SHA, ref, subject or S..C input drift each fail. No `secretstub` tags or Windows assets. Candidate attestations cannot satisfy final release verification.

### 3. Verified installation and launchers (worker B, after 1)

Files: `hooks/guard-go`, `scripts/install-release.sh`, `bin/secret-go`, `tests/test-launchers.sh`. `bin/secret` stays unchanged throughout M4; M4.1 stages the final CLI path in moved item 6.

- Bounded portable `readlink` traversal for relative and absolute symlink chains, `cd -P`/`pwd -P` checkout discovery, quoted paths. Reject cycles, dangling links, aliased cache or manifest destinations and unsafe owners or modes. Permitted entrypoint symlinks do not imply permitted checksum or cache symlinks. Never source checkout metadata or trust a PATH `secret`.
- The installer requires an explicit trusted checkout or release pin, validates the committed checksum manifest, downloads only exact HTTPS tag assets with restricted redirects and size/time limits into 0700 scratch, then verifies digest and authenticated repository/workflow/C/tag/subject before `chmod` and atomic cache publication. C comes from the trusted pin or authenticated tag identity, never a self-referential field at C. Persist bounded names-only verification metadata and attestation material for offline preinstallation; test the pinned `gh` offline trust-root requirements rather than assuming `--bundle` removes network access.
- Exclusive bounded installation lock; clean up only owned temporary state; never steal a stale lock or execute a partial file. Rehash the cached executable before every exec.
- A warm verified cache works offline. Cold offline, wrong digest/version/arch, missing tools, bad provenance and lock timeout deny. Bootstrap denial JSON is dependency-light; a JSON write failure exits 2 with fixed stderr. CLI bootstrap exits nonzero with fixed install guidance. Exec failures and crashes after replacement are the host's responsibility.

Acceptance: focused launcher tests for spaces, relative chains, other cwd, unsafe parents/manifests/cache, warm offline success and cold denial, mismatch, interrupted and concurrent installs, no Bash fallback, and dependency failures without leaking downloader or provider output.

### 4. Hosted install matrix (worker C, after 1; integrates 2 and 3)

Files: `.github/workflows/plugin.yml`, `tests/test-plugin.py`, `testdata/plugin/*.json`. Jobs: `plugin-install-linux`, `plugin-install-macos`, `plugin-manifest-check`, running `python3 -I tests/test-plugin.py ABSOLUTE_CHECKOUT ABSOLUTE_ASSET_DIR`.

Use GitHub-hosted native amd64/arm64 Linux and macOS labels and record actual OS, image and architecture. Without a native runner for an architecture, record cross-build-only evidence and do not advertise native verification. Run the README clone, symlink, version and show flow from another cwd against synthetic stores, with absolute and relative symlink chains.

Matrix: cold verified install, warm offline, cold offline denial, truncated or corrupt download, wrong manifest/digest/version/subject, denied redirects, missing verifier or hash utility, stalled download, lock wait timeout, simultaneous first installs, killed installer and stale-lock guidance. Assert one valid published binary, no partial exec, no fallback, private modes. Fixture transport stays outside production interfaces; repeat installation from the actual published assets before promotion.

Acceptance: assert exit status, JSON and execution witnesses, not error strings alone; missing tests never pass. Run stock macOS `/bin/bash` 3.2, `sh -n` and ShellCheck. Codex hook paths stay unchanged and all four manifest versions equal each other. M4 keeps the installed Bash hook and unreferenced Go launchers. The separate `--stage m4.1` manifest check requires versions equal V and Claude activation; `plugin.yml` does not run it in M4.

### 5. Real host harness (worker D, inactive in M4; evidence in M4.1)

Files: `.github/workflows/host-hooks.yml`, `tests/test-host-hooks.py`, `tests/host-hook-fixture.go`, `testdata/host-hooks/*.json`, `docs/design/host-failure-evidence.md`. Jobs: `claude-host-linux`, `claude-host-macos`, `codex-host-linux`, `codex-host-macos`; protected `workflow_dispatch` with pinned host packages and isolated HOME.

Claude Code documents `onFailure: "block"` since 2.1.295 for startup failures, exits other than 0/2, malformed or schema-invalid JSON and timeout, and supports headless `claude -p` with `--plugin-dir`, `--settings`, `--allowedTools` and structured output. Use a real non-interactive harness on the runner:

```sh
claude -p "$synthetic_prompt" --plugin-dir "$checkout" --settings "$fixture_settings" \
  --allowedTools "Bash,Read,Edit,Write" --output-format stream-json --verbose
```

with bounded session and model spend and only disposable fixture permissions.

- Assert the plugin loaded, a tool call was attempted, the hook failure was reported and the tool did not run. A healthy control must run the identical request, so a missing tool call, absent authentication, policy refusal or missing plugin cannot pass. Use filesystem witnesses for Bash and writes, structured tool-result absence for reads; retain only sanitized synthetic evidence.
- For both synchronous Claude groups test missing launcher, failed or non-executable launcher, missing binary, exec-format error, exit 1, real post-exec Go fatal exit or signal, malformed JSON, schema-invalid JSON, timeout beyond 5s, valid deny and healthy neutral behavior. Fault binaries are test-only and must not ship. Record the actual shell executable and cwd/workdir envelope contract.
- Run the same matrix against pinned Codex with the retained Bash hook and record dispatch, trust/re-trust and omitted workdir. If plugin trust cannot be driven non-interactively, require a documented owner-operated session on a disposable GitHub-hosted runner with sanitized evidence; absent evidence is incomplete, never a pass. No Codex cutover follows even if one version improves.

Acceptance: build and offline-test the harness in M4, keeping model sessions inactive until sponsorship. M4.1 requires real host evidence for every required Claude failure on Linux and macOS. Authentication or model outages block that gate. Synthetic hook subprocess tests never establish host failure blocking. Evidence records version, runner, commit, case and result, never credentials or raw sessions.

### 6. Moved to M4.1: Stage activation and compatibility (after sponsored host evidence)

Entirely out of M4 scope, including manifest versions, `onFailure`, CLI staging and the hook output contract. Do not modify these installed surfaces in M4.

Files: `hooks/hooks.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.codex-plugin/plugin.json`, `.agents/plugins/marketplace.json`, `bin/secret`, `compat/secret`, `.github/workflows/ci.yml`, `tests/test-compat.sh`.

- On the release branch only: quote both Claude `guard-go` commands, keep timeout 5, add `onFailure: "block"` to every synchronous entry and bump all four versions together. Leave `.codex-plugin/hooks.json`, `codex/hooks.json` and `hooks/guard-secrets` on Bash.
- Copy the Bash CLI byte-for-byte to executable `compat/secret`, stage the verified CLI launcher as `bin/secret`, remove `bin/secret-go` if redundant. Point every retained Bash CLI, provider, current-Bash, stock-3.2 and inventory job at absolute `SECRET_CLI=.../compat/secret`, assert the resolved executable identity, and test that a broken `bin/secret` cannot redirect or invalidate the compatibility gate. Keep separate verified-launcher Go integration and exact divergence tests.
- Resolve the output contract in `internal/hook/hook.go`, `internal/hook/hook_test.go` and the `internal/cli` hook dispatch tests: safe Claude requests emit a host-tested neutral response, not an explicit allow that overrides other permission rules; preserve Codex compatibility. Output-write failure and panic paths return denial or nonzero. A zero-exit empty-output fault may remain a host-valid no-decision and must be documented, not claimed as covered by `onFailure`. Regenerate affected expectations only with review.

Acceptance: the existing lint/test/libsecret/keychain/go matrix stays green, the exact corpus is preserved, both Claude groups are exercised through the installed branch plugin, M2 safe/deny semantics are unchanged. All M4.1 activation, version, CLI and build input changes require a new candidate source identity; never alter the frozen M4 S or C.

### 7. Installation and release documentation (coordinator, before S)

Files: `README.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `CHANGELOG.md`, `docs/install.md`, `docs/release.md`, `docs/design/go-rewrite.md`, `internal/feature/doctor.go`, `internal/feature/doctor_test.go`, `testdata/feature/doctor.json`.

Document release and checkout pins, tested Linux/macOS versions and architectures, the Claude Code minimum and tested pin, preinstall and offline procedure, `gh`/hash/download dependencies, a failure table, Codex trust limits and explicit Bash rollback. Remove stale M3-only doctor and release status without treating config presence or a matching checksum as proof of host activation or provenance. Stage guidance before S; record later evidence in GitHub run and release records, not post-S tracked edits. Homebrew publication, if included, is a separate outward action that **requires explicit owner go-ahead**; Scoop stays out of scope.

Acceptance: documented install and Bash-default commands run on hosted runners. Claude Go cutover is unsupported before M4.1; its supported-install preflight must reject older Claude Code. Mark implemented M4 tracker items `(pending CI)` until hosted evidence exists. Mark M4 done only in a later tracking PR after the final applicable hosted gate, with run links, never by changing C.

## Exit gate and irreversible sequence

1. Two independently green integrated M4 candidates, covering reproducibility, the install matrix, offline synthetic host classification and all retained CI. Real model sessions are inactive and not an M4 required check. Candidates use disposable checksum metadata and are never published as final-tag provenance. Freeze the Bash-default source S only after both pass; any later source, config or build change restarts candidates and S.
2. Build S twice in hosted CI with its fixed epoch, compare every byte, and commit only `dist/checksums-v<V>.txt` as signed checksum commit C. Check the exact S..C diff. The branch stays unpromoted; the installed default stays Bash.
3. Create and push the immutable protected annotated tag `v<V>` at C: **requires explicit owner go-ahead**. Final-tag jobs rebuild twice from C, compare with the committed S digests, attest and verify C/tag subjects. A failure means a new release identity, never retagging.
4. Create a draft GitHub Release with verified assets and bundles: **requires explicit owner go-ahead**. Verify uploaded bytes and provenance. Publish it: **requires explicit owner go-ahead**. Then run final public cold, offline, corruption and install tests on hosted runners. Real host tests remain deferred to M4.1; publishing does not authorize default promotion.
5. M4 may promote only its unchanged Bash-default installation surfaces after those checks: **requires explicit owner go-ahead**. Bumped manifests, `onFailure: "block"`, Go CLI staging with `compat/secret`, `guard-go` activation and hook output-contract changes all belong to M4.1 after sponsored host evidence. Any default-branch setting change also **requires explicit owner go-ahead**. M4.1 must repeat applicable candidate and release gates for its new source identity; it cannot mutate the immutable M4 tag.

## Residual risks

- Trusted checkout provenance is the bootstrap root; a checksum beside a compromised binary is not independent trust.
- Shell pathname checks cannot eliminate same-user TOCTOU.
- Missing or killed launcher protection belongs to the host; empty successful output can be valid.
- Cold network verification may exceed the host timeout, so explicit preinstall and denial are expected.
- Model or authentication availability and Codex trust automation can block hosted evidence.
- Keep rollback and differential CI after M4.1 cutover and for two successful shipped releases, not merely two candidates. M6 maintenance-only status and retirement need their own gates; never remove Codex's installed Bash guard while hook failures remain open.

Sources: <https://code.claude.com/docs/en/hooks>, <https://code.claude.com/docs/en/headless>, <https://cli.github.com/manual/gh_attestation_verify>. They establish supported harness mechanisms, not that this repository's host tests pass.
