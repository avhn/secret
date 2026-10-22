# Installation, pins and rollback

## What is installed today

The installed default `bin/secret` and the Claude and Codex plugin hooks remain
Bash. All four marketplace/plugin versions remain equal at 0.1.0. M4 adds release
tooling and opt-in `bin/secret-go` and `hooks/guard-go`; no manifest references
those launchers. Claude cutover, version bumps, `onFailure: "block"`, the
`compat/secret` path and the Go hook output contract belong entirely to M4.1.
Do not edit a local hook to activate Go based on a cache or doctor report.

M4 is in progress, pending hosted CI and release approval. No v0.2.2 release or
committed checksum manifest is available yet. The release procedure below is for
an approved, published final tag, not a command to run against a candidate branch.
See [release.md](release.md) for owner approval boundaries.

## Current Bash installation

Use the [README installation](../README.md#install) for the Bash CLI and plugins.
Bash needs Bash 3.2+, Perl, and jq for the guard. Install ripgrep's protective
configuration as documented there. Create `~/.local/bin` before making the CLI
symlink. For a reproducible checkout, fetch and review a full commit ID, then use
`git checkout --detach FULL_REVIEWED_COMMIT` rather than following a moving branch.
Review plugin updates before use. Codex hooks need explicit trust in `/hooks` and
re-trust after changes; listed but untrusted hooks do not execute. Codex's hook
failure behavior is not proven to block tools.

## Release and platform pins

Release identity is fixed at V=0.2.2, annotated tag `v0.2.2`, source commit S and
checksum-only child commit C. The trusted checkout must be exactly the full C
which the annotated tag peels to. Obtain C from separately authenticated owner
release records, not a field inside the downloaded binary or its checksum file.
Never use a `latest` URL, candidate S attestation or an arbitrary PATH `secret`.

| Platform | Asset suffixes | Native hosted targets | Evidence status |
| --- | --- | --- | --- |
| Linux | linux-amd64, linux-arm64 | ubuntu-latest (record ImageOS), ubuntu-24.04-arm | Local Linux amd64 synthetic checks; hosted versions/arches pending CI |
| macOS | darwin-amd64, darwin-arm64 | macos-15-intel, macos-latest (record sw_vers) | Both native architectures and stock /bin/bash 3.2 pending hosted CI |
| Windows | none | Development CI only | No release or protection claim |

`release.yml` uses Ubuntu 24.04 for independent cross-builds. A cross-build is not
native execution evidence. `plugin.yml` records `uname -srm`, `sw_vers` on macOS,
ImageOS/ImageVersion and RUNNER_ARCH; the passing run records, not mutable runner
label names, establish the tested OS versions and architectures. No hosted
Linux/macOS version is certified by this branch before those jobs pass.

The release build pin is Go 1.26.0 with `GOTOOLCHAIN=local`; consumers need no Go
compiler. Future Claude activation requires at least Claude Code 2.1.295, initially
pinned to exactly 2.1.295; older hosts are unsupported for Go cutover. The inactive
host harness pins Codex 0.163.0, but this is not a claim of tested host protection.
No model sessions have run. See [host evidence](design/host-failure-evidence.md).

## Explicit preinstallation after publication

Run only from a trusted, reviewed checkout at C. These instructions do not
install hooks or change the Bash default. Production verification needs Git,
Python 3, POSIX sh, ordinary GNU/BSD utilities (`readlink`, `stat`, `awk`, `cmp`,
`mktemp`, and file/mode utilities), plus `sha256sum` or `shasum -a 256`.
Cold verification also needs GitHub CLI `gh` with `attestation download`,
`attestation trusted-root`, and `attestation verify` supporting `--source-digest`,
`--source-ref`, `--bundle`, `--custom-trusted-root` and JSON output. Local synthetic
checks use gh 2.102.0. The read-only release rehearsal exercises genuine public
v0.2.1 provenance with identity-substituted new scripts; real v0.2.2 provenance
and published-assets/offline behavior remain hosted gates. Online downloading
additionally needs curl with HTTPS, redirect, connect and total-time limits. Install these tools through your trusted
OS/package channel; do not pipe downloaded scripts to a shell.

```sh
# In the trusted checkout, after independently authenticating C and the tag:
git checkout --detach FULL_AUTHENTICATED_C
git fetch --no-tags --force origin "refs/tags/v0.2.2:refs/tags/v0.2.2"
test "$(git cat-file -t refs/tags/v0.2.2)" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse 'refs/tags/v0.2.2^{commit}')"
sh scripts/verify-release.sh --source
sh scripts/install-release.sh
./bin/secret-go version
```

The explicit fetch restores only the local annotated tag after checkout. The
installer itself never fetches tags, including on warm or offline paths, and
rejects lightweight tags rather than weakening the pin.

The installer fetches only the exact platform asset under
`https://github.com/avhn/secret/releases/download/v0.2.2/`. It checks the committed
four-line checksum manifest, provenance repository `avhn/secret`, signer workflow
`.github/workflows/release.yml`, source C, tag ref, certificate issuer and subject
name/digest before execution. The checkout is the bootstrap trust root; a matching
checksum alone is not independent provenance.

The verifier keeps `--repo avhn/secret`, `--source-digest C`,
`--signer-digest C`, `--source-ref refs/tags/v0.2.2`,
`--cert-oidc-issuer https://token.actions.githubusercontent.com`, the exact SAN
`--cert-identity https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.2.2`
and `--deny-self-hosted-runners`. Do not add `--signer-workflow`: gh 2.102.0
rejects it together with `--cert-identity`. The exact SAN already pins the
same-repository signer workflow and tag. Likewise, use `--repo`, not both
`--repo` and `--owner`, for verification or attestation download.

Cache location is `${XDG_CACHE_HOME:-$HOME/.cache}/secret/v0.2.2/`. Keep it on a
user-owned direct path with private directories (0700); `secret` is 0500 and
names-only `verified` metadata is 0600. Do not symlink cache or checksum paths.
The launchers resolve bounded entrypoint symlink chains and rehash before every
exec. They do not trust PATH binaries or silently fall back to Bash.

## Pre-downloaded and offline installation

On an online trusted machine, acquire each binary in its own new empty directory.
Acquire its attestation with `gh attestation download /absolute/path/to/ASSET
--repo avhn/secret` from a separate fresh empty bundle directory. Keep scripts
outside downloaded directories; run Python readers with `-I`. Assemble only the
reviewed asset and its `sha256:DIGEST.jsonl` bundle in a private input directory.
GitHub Release bundles use portable `sha256-DIGEST.jsonl` asset names; rename the
reviewed local copy to gh's colon form before `--from-dir` use.
Then, from the trusted checkout, run:

```sh
sh scripts/install-release.sh --from-dir /absolute/private/release-input
# Once installed, this verifies the warm cache without downloading:
sh scripts/install-release.sh --offline
./bin/secret-go version
```

`--from-dir` still verifies provenance and can contact the trust service unless
`--offline` is given. During online preinstallation the installer runs
`gh attestation trusted-root` using gh's authenticated TUF bootstrap and saves
the result privately in the versioned cache. It does not use a root from the
input directory. A cold air-gapped install requires the authenticated
`trusted_root.jsonl` previously acquired by a successful online preinstallation
and retained as a private 0600 file in that same versioned cache, plus the exact
asset and digest-named attestation bundle. Preserve that trust file when
reprovisioning; do not invent one from an unauthenticated JSON file. With those
inputs, `sh scripts/install-release.sh --from-dir /absolute/private/release-input
--offline` re-verifies using gh's custom trusted root. A bundle alone is not
sufficient. Missing trust fails rather than bootstrapping over the network.
The published-assets workflow removes the cached executable/metadata before
checking this path with the real verifier and a network witness. It has not run
yet; candidate fixture installs do not prove offline provenance.

A warm cache can run offline. Cold offline without local inputs denies. Do not
use `SECRET_RELEASE_TEST_ROOT` or create `.secret-release-test-fixture` in a real
checkout. That pair is only for disposable synthetic tests; no shipped tree may
contain the marker, including as a dangling symlink.

## Failure and recovery table

| Failure | Observable result | Recovery |
| --- | --- | --- |
| Missing/cold cache, unsupported platform or digest mismatch in CLI launcher | Exit 70, fixed install guidance | Check trusted C, dependencies and platform, then explicitly reinstall |
| Pre-exec hook bootstrap failure | Exit 0 with fixed deny JSON; exit 2 if JSON cannot be written | Preinstall explicitly; this is not a host-spawn guarantee |
| Installer malformed checksum, corrupt asset, wrong provenance or missing offline trust | Exit 1, fixed installation failure | Reacquire authenticated inputs; never bypass validation |
| Installer bad arguments | Exit 2, usage | Use the documented arguments |
| Installer lock timeout or killed previous owner | Exit 3, stale-lock guidance | Verify owner process and token manually before removing the lock; never steal it automatically |
| Installer unsupported platform or missing dependency | Exit 4 | Use a supported OS/arch and trusted dependencies |
| Hook cannot start, exec fails, crashes, times out or emits invalid output after exec | Host-dependent, unproven here | Retain Bash installation until M4.1 host evidence; do not claim fail-closed protection |

Doctor inspects explicit metadata only. A launcher/config/cache present on disk,
a matching supplied digest or a names-only `verified` file proves neither host
activation nor release provenance. It does not contact a host or repair stores.

## Explicit Bash rollback

Until M4.1, the existing `bin/secret` is itself the Bash rollback. Keep a reviewed
Bash checkout alongside any opt-in Go installation. Invoke its absolute
`/absolute/trusted/bash-checkout/bin/secret` or point a separate test symlink there;
never change behavior automatically on a Go failure. Existing Claude and Codex
manifests already reference `hooks/guard-secrets`. If you changed experimental
local configuration, restore the reviewed Bash config manually, restart the host
and review/re-trust Codex hooks. M4 does not create `compat/secret`; that explicit
compatibility path and its CI belong to M4.1. No rollback procedure grants an
agent permission to retrieve values or install hooks into your real HOME.
