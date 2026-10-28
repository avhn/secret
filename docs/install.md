# Installation, pins and rollback

## What is installed today

The installed default `bin/secret` and Claude/Codex plugin hooks remain Bash.
The v0.3.0 packaging update independently bumps all four marketplace/plugin
versions to 0.3.0; this is not Go activation. Opt-in standalone installers publish
`secret-go` or `secret-go.exe`, while trusted checkouts retain `bin/secret-go`
and `hooks/guard-go`. No installed manifest references those launchers.
Claude cutover, `onFailure: "block"`, `compat/secret` and Go hook output-contract
changes remain M4.1, waiting sponsorship. Do not activate Go hooks based on
an executable, cache, MCP registration or doctor report.

M4 is complete: [v0.2.3](https://github.com/avhn/secret/releases/tag/v0.2.3)
was published on 2026-10-24, at checksum commit C
`79980020b3ffaea14833684592ffa2c97d78aae0` from source S `7141a13`.
The [recorded release evidence](../ROADMAP.md#m4-releasable-linuxmacos-core)
includes native published-asset installs on all four Linux/macOS targets.
That historical evidence does not certify the new Windows assets or Desktop
bundle. The procedure below targets the planned v0.3.0 final tag after its
separate owner-approved publication; do not use a candidate branch as C.
See [release.md](release.md) for owner approval boundaries and
[canonical MCP setup](setup.md) for per-client registration.

## Current Bash installation

Use the [README installation](../README.md#install) for the Bash CLI and plugins.
Bash needs Bash 3.2+, Perl, and jq for the guard. Install ripgrep's protective
configuration as documented there. Create `~/.local/bin` before making the CLI
symlink. For a reproducible checkout, fetch and review a full commit ID, then use
`git checkout --detach FULL_REVIEWED_COMMIT` rather than following a moving branch.
Review plugin updates before use. Codex hooks need explicit trust in `/hooks` and
re-trust after changes; listed but untrusted hooks do not execute. Codex's hook
failure behavior is not proven to block tools.

## Standalone install and bootstrap trust

The pinned Linux/macOS and PowerShell bootstrap snippets are in [setup.md](setup.md#install).
`install.sh` needs Python 3, curl and gh; `install.ps1` needs Windows PowerShell,
curl.exe and gh. gh must already be authenticated: run `gh auth login` yourself
in a private terminal, or supply `GH_TOKEN` through your trusted credential
environment without displaying it. Never paste a token into chat or client
configuration. Install dependencies through trusted channels. The bootstrap
trusts GitHub HTTPS, repository/tag governance and the installer before payload
verification. Download/review/run or a reviewed checkout offers stronger bootstrap
review; this is not cryptographically verified script execution.

The PowerShell snippet runs the downloaded file in a child process of the same
host using `-NoProfile -ExecutionPolicy Bypass`, preserves its exit code and
cleans up in `finally`. The bypass applies only to that one child process, not
persistent policy. It permits execution under Windows PowerShell 5.1's default
Restricted policy; centrally enforced Group Policy can still take precedence.

Inputs: `SECRET_VERSION` defaults to `0.3.0`, never latest;
`SECRET_RELEASE_COMMIT` optionally supplies an independently authenticated full
lowercase 40-hex C; `INSTALL_DIR` selects the destination. Equivalent file-mode
flags are `--version`, `--commit`, `--dir` and `--help`. Conflicting pins fail.
Without an explicit C, both scripts derive it only from verified attestation
identity and require checksum and binary provenance to agree. gh is mandatory;
missing gh never enables a checksum-only fallback. Digest, architecture and
`secret 0.3.0 (go)` are checked before atomic publication.

Unix defaults to `~/.local/bin/secret-go` without PATH/profile edits. Windows
defaults to `%LOCALAPPDATA%\Programs\secret\secret-go.exe` and adds only its own
directory to user PATH; open a new terminal afterward. Neither edits client
configuration, registers MCP, reads stores, installs hooks or overwrites Bash
`secret`. Unsafe ownership/modes, reparse points, DACLs and aliases are rejected;
arbitrary existing parents are not repaired. Stop clients before replacement,
especially Windows open-image replacement. Locks are tokened and never stolen.

The raw standalone executable has install-time verification, not the checkout
launcher's per-execution rehash. The standalone installers are online-only and
have no `--offline` or `--from-dir` mode. Windows cold offline installation is
not supported. The separate Unix trusted-checkout cache retains the explicit
offline interfaces below.

## Release and platform pins

Release identity is fixed at V=0.3.0, annotated tag `v0.3.0`, source commit S and
checksum-only child commit C. The trusted checkout must be exactly the full C
which the annotated tag peels to. Obtain C from separately authenticated owner
release records, not a field inside the downloaded binary or its checksum file.
Never use a `latest` URL, candidate S attestation or an arbitrary PATH `secret`.

| Platform | Asset suffixes | Native hosted targets | Evidence status |
| --- | --- | --- | --- |
| Linux | linux-amd64, linux-arm64 | ubuntu-latest (record ImageOS), ubuntu-24.04-arm | Prior v0.2.3 installs passed; new v0.3.0 candidate/public installs required |
| macOS | darwin-amd64, darwin-arm64 | macos-15-intel, macos-latest (record sw_vers) | Prior v0.2.3 installs and Bash 3.2 passed; new v0.3.0 gates required |
| Windows | windows-amd64.exe, windows-arm64.exe | windows-latest, windows-11-arm | M5a amd64 runtime gate passed; v0.3.0 native candidate/public installs on both architectures remain required |

All six are raw executables named `secret-v0.3.0-SUFFIX`, not archives. The other
payloads are `secret-v0.3.0-desktop.mcpb` and generated `server.json`. The sorted
`checksums-v0.3.0.txt` has exactly eight payload records; nine attestation bundles
cover those payloads plus the checksum asset. There are eighteen public assets.
The Desktop bundle contains macOS universal and Windows amd64 payloads only;
actual Desktop installation is not host-tested. Registry name:
`io.github.avhn/secret` (publication is separately owner-gated).

`release.yml` uses independent hosted macOS builds for native lipo assembly.
Release tooling pins Go 1.26.10, Node 26.10.0, npm 11.19.1 and Python 3.14.8,
with locked MCPB 2.1.2 and `npm ci --prefix packaging/mcpb --ignore-scripts`.
See [release tooling security](release.md#packaging-tools-and-advisory-review)
for the narrowly reviewed build-only Zod advisory exception. End users need none
of those packaging dependencies. A cross-build is not native execution evidence. `plugin.yml` records `uname -srm`, `sw_vers` on macOS,
ImageOS/ImageVersion and RUNNER_ARCH; the passing run records, not mutable runner
label names, establish the tested OS versions and architectures. The published
v0.2.3 install evidence is [run 40130118807](https://github.com/avhn/secret/actions/runs/40130118807);
subsequent changes still require their applicable native jobs.

The release build pin is Go 1.26.10 with `GOTOOLCHAIN=local`; consumers need no Go
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
`--source-ref`, `--bundle`, `--custom-trusted-root` and JSON output. Authenticate
gh with `gh auth login` in your private terminal or an already configured
`GH_TOKEN`; attestation verification requires authentication even for public
release assets. Do not paste or print the token. Local synthetic checks use
gh 2.102.0. The earlier read-only rehearsal used genuine v0.2.2
provenance with identity-substituted scripts. The published v0.2.3 workflow passed
its historical four-target checks; it is not evidence for the v0.3.0 integrated
artifacts or Windows installs. Online downloading additionally needs curl with
HTTPS, redirect, connect and total-time limits. Install these tools through your
trusted OS/package channel. This checkout path does not execute a downloaded
bootstrap script.

```sh
# In the trusted checkout, after independently authenticating C and the tag:
git checkout --detach FULL_AUTHENTICATED_C
git fetch --no-tags --force origin "refs/tags/v0.3.0:refs/tags/v0.3.0"
test "$(git cat-file -t refs/tags/v0.3.0)" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse 'refs/tags/v0.3.0^{commit}')"
sh scripts/verify-release.sh --source
sh scripts/install-release.sh
./bin/secret-go version
```

The explicit fetch restores only the local annotated tag after checkout. The
installer itself never fetches tags, including on warm or offline paths, and
rejects lightweight tags rather than weakening the pin.

The installer fetches only the exact platform asset under
`https://github.com/avhn/secret/releases/download/v0.3.0/`. It checks the committed
eight-line checksum manifest, provenance repository `avhn/secret`, signer workflow
`.github/workflows/release.yml`, source C, tag ref, certificate issuer and subject
name/digest before execution. The checkout is the bootstrap trust root; a matching
checksum alone is not independent provenance.

The verifier keeps `--repo avhn/secret`, `--source-digest C`,
`--signer-digest C`, `--source-ref refs/tags/v0.3.0`,
`--cert-oidc-issuer https://token.actions.githubusercontent.com`, the exact SAN
`--cert-identity https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.3.0`
and `--deny-self-hosted-runners`. Do not add `--signer-workflow`: gh 2.102.0
rejects it together with `--cert-identity`. The exact SAN already pins the
same-repository signer workflow and tag. Likewise, use `--repo`, not both
`--repo` and `--owner`, for verification or attestation download.

Cache location is `${XDG_CACHE_HOME:-$HOME/.cache}/secret/v0.3.0/`. Keep it on a
user-owned direct path with private directories (0700); `secret` is 0500 and
names-only `verified` metadata is 0600. Do not symlink cache or checksum paths.
The launchers resolve bounded entrypoint symlink chains and rehash before every
exec. They do not trust PATH binaries or silently fall back to Bash.

## Verify the complete release, including Desktop MCPB

From the independently authenticated checkout at C, acquire all eight payloads
and `checksums-v0.3.0.txt`, each initially into its own new empty directory, then
assemble only those reviewed inputs into a private asset directory. Download
all nine portable `sha256-DIGEST.jsonl` bundles into separate fresh directories
and assemble them in a private bundle directory. Keep scripts outside all
untrusted input directories and run Python readers with `-I`. Then run:

```sh
sh scripts/verify-release.sh /absolute/private/assets FULL_AUTHENTICATED_C \
  --bundle-dir /absolute/private/bundles
```

This rechecks committed checksums, annotated tag/C, the exact S..C boundary and
all nine subjects with gh, including the MCPB and generated server.json. It
accepts portable bundle filenames directly; do not create ambiguous colon and
portable copies for the same digest. It may contact the trust service: a local
bundle does not itself make verification offline or establish trust. Only use
the verified bundle afterward in Desktop; this does not prove host compatibility.

## Pre-downloaded and offline installation

On an online trusted machine, acquire each binary in its own new empty directory.
Acquire its attestation with `gh attestation download /absolute/path/to/ASSET
--repo avhn/secret` from a separate fresh empty bundle directory. Keep scripts
outside downloaded directories; run Python readers with `-I`. Assemble only the
reviewed asset and its `sha256:DIGEST.jsonl` bundle in a private input directory.
GitHub Release bundles use portable `sha256-DIGEST.jsonl` asset names.
The Unix checkout installer expects gh's `sha256:DIGEST.jsonl` local form; rename
only the reviewed scratch copy for `--from-dir`. Windows cannot use colon
filenames and uses its separate native installer, not this Unix cache path.
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
checking this path with the real verifier and a network witness. The v0.3.0 path
still requires its own public-asset run; candidate fixture installs do not prove
offline provenance.

A warm cache can run offline. Cold offline without local inputs denies. Do not
use `SECRET_RELEASE_TEST_ROOT` or create `.secret-release-test-fixture` in a real
checkout. That pair is only for disposable synthetic tests; no shipped tree may
contain the marker, including as a dangling symlink.

## Failure and recovery table

The numbered installer exits in this table apply only to the trusted-checkout
`scripts/install-release.sh`, not the standalone bootstrap installers.

| Failure | Observable result | Recovery |
| --- | --- | --- |
| Missing/cold cache, unsupported platform or digest mismatch in CLI launcher | Exit 70, fixed install guidance | Check trusted C, dependencies and platform, then explicitly reinstall |
| Pre-exec hook bootstrap failure | Exit 0 with fixed deny JSON; exit 2 if JSON cannot be written | Preinstall explicitly; this is not a host-spawn guarantee |
| `scripts/install-release.sh`: malformed checksum, corrupt asset, wrong provenance or missing offline trust | Exit 1, fixed installation failure | Reacquire authenticated inputs; never bypass validation |
| `scripts/install-release.sh`: bad arguments | Exit 2, usage | Use the documented arguments |
| `scripts/install-release.sh`: lock timeout or killed previous owner | Exit 3, stale-lock guidance | Verify owner process and token manually before removing the lock; never steal it automatically |
| `scripts/install-release.sh`: unsupported platform or missing dependency | Exit 4 | Use a supported OS/arch and trusted dependencies |
| Hook cannot start, exec fails, crashes, times out or emits invalid output after exec | Host-dependent, unproven here | Retain Bash installation until M4.1 host evidence; do not claim fail-closed protection |

Standalone behavior is separate:

- `install.sh` exits 1 for failures caught by its Python entrypoint, including
  arguments, dependencies other than Python, unsupported platforms, verification
  and locks. Missing Python 3 exits 4 before that entrypoint. Successful install
  and `--help` return 0; it does not expose the checkout installer's 2/3/4 taxonomy.
- `install.ps1` uses terminating PowerShell errors (`throw`, with
  `$ErrorActionPreference = 'Stop'`), not that numbered taxonomy. A terminating
  failure propagates to the caller; numeric process status depends on how the
  host invokes PowerShell (for example, a failing `-File` invocation exits 1).
  Successful install and help return normally. Do not infer success from a
  previous native command's `$LASTEXITCODE` after an in-process script call.
- The [bootstrap snippets](setup.md#install) download before execution. POSIX
  preserves curl's nonzero download status (for example 22 for an HTTP failure)
  through cleanup and never starts the installer on that failure. PowerShell
  uses `-ErrorAction Stop` before starting the same host's child process, saves
  `$LASTEXITCODE`, cleans up in `finally` and exits with the saved child status.
  A failed download remains a terminating error, not an empty successful install.
  `-ExecutionPolicy Bypass` applies only to that child, with no persistent change.

If a standalone installer reports
`secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry`,
authenticate gh in your own private terminal or correct its trusted credential
environment, then retry. No token value is needed in chat, logs or client config.

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
