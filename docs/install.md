# Installation, pins and rollback

## What is installed today

From v0.4.0 onward, the final CLI name is `secret` on Unix and `secret.exe` on Windows. The
owner-approved CLI-only extraction from M4.1 puts the verified Go launcher at
`bin/secret` and retains byte-identical executable Bash at `compat/secret`.
v0.5.0 is prepared and unreleased. Published
tags and assets are immutable; fixes require a new patch version.
Claude and Codex plugin hooks remain Bash. `hooks/guard-go` stays inactive.
Claude cutover, `onFailure: "block"` and Go hook output-contract changes
remain M4.1, waiting sponsorship. Do not activate Go hooks based on
an executable, cache, MCP registration or doctor report.

M4 is complete: [v0.2.3](https://github.com/avhn/secret/releases/tag/v0.2.3)
was published on 2026-10-24, at checksum commit C
`79980020b3ffaea14833684592ffa2c97d78aae0` from source S `7141a13`.
The [recorded release evidence](../ROADMAP.md#m4-releasable-linuxmacos-core)
includes native published-asset installs on all four Linux/macOS targets.
That historical evidence does not certify the new Windows assets or Desktop
bundle. The checkout procedure below targets v0.5.0 after publication; do not use a candidate branch as C.
See [release.md](release.md) for owner approval boundaries and
[canonical MCP setup](setup.md) for per-client registration.

## Checkout installation and Bash compatibility


Requirements: bash 3.2 or newer (stock macOS bash works), perl, and jq for the
guard and explicit `compat/secret` rollback. The final CLI is Go; CLI naming
does not activate Go hooks or change MCP registration.

The checkout `bin/secret` launcher requires a release checksum commit C with
its committed checksum manifest. It works at an authenticated release tag that
includes this change, **v0.4.0 onward**, after verified cache installation. A
plain main checkout has no current release checksum manifest and exits 70;
it does not build from source or fall back to Bash.

For main/clone users, use the standalone installer above (and its printed path),
or explicitly select the retained Bash implementation:

```bash
git clone https://github.com/avhn/secret ~/.local/share/secret
bash ~/.local/share/secret/compat/secret help
```

For a released checkout launcher, first select the authenticated release C as
shown in [installation](install.md), then preinstall its verified cache and
link that release checkout's `bin/secret`. Do not link main's launcher expecting
it to work without release metadata.

The guard and skill, as a Claude Code plugin:

```text
/plugin marketplace add avhn/secret
/plugin install secret@secret
```

For Codex CLI, install the plugin from this repository's Codex marketplace.
It bundles the guard and skill, without modifying `~/.codex/hooks.json`:

```bash
codex plugin marketplace add avhn/secret
codex plugin add secret@secret
```

In Codex, open `/hooks` and trust the installed secret hook before relying on
it. Untrusted hooks are listed but do not run; review and re-trust the hook
when it changes. `/plugins` lets you inspect the installed plugin. The plugin
does not put `bin/secret` on `PATH`. Install the CLI separately if you want to
use it. Main/clone users should choose the standalone installer or invoke
`bash ~/.local/share/secret/compat/secret` explicitly. A `bin/secret` symlink
requires an authenticated v0.4.0-or-later release checkout at C, not main, plus
its verified cache and `~/.local/bin` on `PATH`.

If your Codex version has no plugin marketplace support, use the manual route
with a checkout of the repo. Copy the hook template with an absolute command
path and install the skill in the user skills root:

```bash
mkdir -p ~/.codex ~/.codex/skills
jq --arg command "$HOME/.local/share/secret/hooks/guard-secrets" \
  '.hooks.PreToolUse[].hooks[].command = $command' \
  ~/.local/share/secret/codex/hooks.json >~/.codex/hooks.json
ln -s ~/.local/share/secret/skills/secrets ~/.codex/skills/secrets
```

If `~/.codex/hooks.json` already exists, merge its `PreToolUse` groups rather
than replacing the file. Codex also accepts inline `[hooks]` in `config.toml`;
the snippet uses `hooks.json` so it can be copied without changing that file.
Open `/hooks` to trust the manual hook as well. Codex sends shell commands
under the `Bash` hook name and patches under `apply_patch`. The guard needs
`jq` and `perl` on the hook's `PATH`.

The guard allows plain `rg` because ripgrep can be told to skip store files.
Install the protective config, or merge its globs into your own:

```bash
mkdir -p ~/.config/ripgrep
cp ~/.local/share/secret/examples/ripgreprc ~/.config/ripgrep/config
export RIPGREP_CONFIG_PATH="$HOME/.config/ripgrep/config"  # in your shell profile
```

For a reproducible checkout, fetch and review a full commit ID, then use
`git checkout --detach FULL_REVIEWED_COMMIT` rather than following a moving branch.
Review plugin updates before use. Codex hook failure behavior is not proven to
block tools.

## Standalone install and bootstrap trust

The one-liners are in [setup.md](setup.md#install).

The script defaults to the latest release, resolved once from GitHub's release
redirect, then downloads only that explicit tag. No GitHub account, gh, Python
or credentials are required. Unix needs POSIX sh, curl, standard GNU/BSD utilities
and sha256sum or shasum. Windows needs PowerShell 5.1 or 7 and curl.exe.
Install dependencies through trusted channels.

Set `SECRET_VERSION` to a strict release version (optional leading `v`) to pin
or roll back. File invocations also accept `--version V`, `--dir DIR` and
`--help`; conflicting environment and flag pins fail. `INSTALL_DIR` selects the
destination. For `irm | iex`, set `SECRET_VERSION` and `INSTALL_DIR` in that
PowerShell process, rather than appending file parameters. `--commit` and
`SECRET_RELEASE_COMMIT` were removed and fail with a link to checkout verification
in docs/install.md. No installer changes execution policy.

Unix defaults to `~/.local/bin/secret` and does not edit PATH or profiles.
Windows defaults to `$HOME\.local\bin\secret.exe`, with the native user profile
as fallback when HOME is absent, and adds only its install directory to user
PATH once. Open a new terminal afterward. Both print the concrete executable
path. Neither reads stores, registers MCP, installs hooks or edits clients.

Rerunning updates to latest. Under the tokened lock, a matching installed digest
is a no-op that preserves file identity, mtime and Windows PATH. Otherwise a new
binary is downloaded, checksum/format/architecture/version-checked and atomically
published. The existing executable is never run. Pre-v0.5.0 downloads are checked with
`secret version`, because those releases lack the new `--version` alias. Explicit pins permit rollback;
a corrupt safe installation is repaired. Verification failures preserve the old
file. Unsafe ownership, writable ancestors, aliases, reparse points and DACLs are
rejected, not repaired. Locks are never stolen. Stop clients before replacement,
especially on Windows where an open executable can block atomic replacement.

The one-liners trust GitHub HTTPS, repository/tag governance and the script before
payload verification. `curl | sh` cannot guarantee a complete download before
execution; the function wrapper mitigates truncation, but is not a complete-download
guarantee. A pinned script URL does not pin the default binary release. Download
and review the script first, or use the stronger trusted-checkout route.
HTTPS checksums detect corruption, not a compromised release publisher. The
standalone installers do not verify attestations or provenance and do not rehash
themselves on each run. They have no offline or source-build fallback.

For optional manual provenance verification, install gh separately and run
`gh attestation verify FILE --repo avhn/secret` on the downloaded asset. This does
not by itself establish the full source-S/checksum-C boundary. The stronger
[checkout verification](install.md#release-and-platform-pins) below pins an
independently authenticated C and checks the release workflow, tag and inventory.

## Release and platform pins

Release identity is fixed at V=0.5.0, annotated tag `v0.5.0`, source commit S and
checksum-only child commit C. The trusted checkout must be exactly the full C
which the annotated tag peels to. Obtain C from separately authenticated owner
release records, not a field inside the downloaded binary or its checksum file.
For this stronger checkout route, never use a `latest` URL, candidate S attestation or an arbitrary PATH `secret`.

| Platform | Asset suffixes | Native hosted targets | Evidence status |
| --- | --- | --- | --- |
| Linux | linux-amd64, linux-arm64 | ubuntu-latest (record ImageOS), ubuntu-24.04-arm | Prior v0.2.3 installs passed; new v0.5.0 candidate/public installs required |
| macOS | darwin-amd64, darwin-arm64 | macos-15-intel, macos-latest (record sw_vers) | Prior v0.2.3 installs and Bash 3.2 passed; new v0.5.0 gates required |
| Windows | windows-amd64.exe, windows-arm64.exe | windows-latest, windows-11-arm | M5a amd64 runtime gate passed; v0.5.0 native candidate/public installs on both architectures remain required |

All six are raw executables named `secret-v0.5.0-SUFFIX`, not archives. The other
payloads are `secret-v0.5.0-desktop.mcpb` and generated `server.json`. The sorted
`checksums-v0.5.0.txt` has exactly eight payload records; nine attestation bundles
cover those payloads plus the checksum asset. There are eighteen public assets.
The Desktop bundle contains macOS universal and Windows amd64 payloads only;
actual Desktop installation is not host-tested. Registry name:
`io.github.avhn/secret` (publication is separately owner-gated).

`release.yml` uses independent hosted macOS builds for native lipo assembly.
Release tooling pins Go 1.27.3, Node 26.10.0, npm 11.19.1 and Python 3.14.8,
with locked MCPB 2.1.2 and `npm ci --prefix packaging/mcpb --ignore-scripts`.
See [release tooling security](release.md#packaging-tools-and-advisory-review)
for the narrowly reviewed build-only Zod advisory exception. End users need none
of those packaging dependencies. A cross-build is not native execution evidence. `plugin.yml` records `uname -srm`, `sw_vers` on macOS,
ImageOS/ImageVersion and RUNNER_ARCH; the passing run records, not mutable runner
label names, establish the tested OS versions and architectures. The published
v0.2.3 install evidence is [run 40130118807](https://github.com/avhn/secret/actions/runs/40130118807);
subsequent changes still require their applicable native jobs.

The release build pin is Go 1.27.3 with `GOTOOLCHAIN=local`; consumers need no Go
compiler. Future Claude activation requires at least Claude Code 2.1.295, initially
pinned to exactly 2.1.295; older hosts are unsupported for Go cutover. The inactive
host harness pins Codex 0.163.0, but this is not a claim of tested host protection.
No model sessions have run. See [host evidence](design/host-failure-evidence.md).

## Explicit preinstallation after publication

Run only from a trusted, reviewed checkout at C. These instructions do not
install hooks or change the retained Bash hook default. Production verification needs Git,
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
its historical four-target checks; it is not evidence for the v0.5.0 integrated
artifacts or Windows installs. Online downloading additionally needs curl with
HTTPS, redirect, connect and total-time limits. Install these tools through your
trusted OS/package channel. This checkout path does not execute a downloaded
bootstrap script.

```sh
# In the trusted checkout, after independently authenticating C and the tag:
git checkout --detach FULL_AUTHENTICATED_C
git fetch --no-tags --force origin "refs/tags/v0.5.0:refs/tags/v0.5.0"
test "$(git cat-file -t refs/tags/v0.5.0)" = tag
test "$(git rev-parse HEAD)" = "$(git rev-parse 'refs/tags/v0.5.0^{commit}')"
sh scripts/verify-release.sh --source
sh scripts/install-release.sh
./bin/secret version
```

The commands above target the authenticated v0.5.0 release tag/C and its final
`bin/secret` launcher. Published v0.3.4 instead uses `bin/secret-go`, while its
`bin/secret` is Bash. Main is source S, not release C: without the
committed release checksum manifest its launcher exits 70, even with a cache.
Main/clone users must use the standalone installer and its printed executable
path, or explicitly invoke `compat/secret` for Bash.

The explicit fetch restores only the local annotated tag after checkout. The
installer itself never fetches tags, including on warm or offline paths, and
rejects lightweight tags rather than weakening the pin.

The installer fetches only the exact platform asset under
`https://github.com/avhn/secret/releases/download/v0.5.0/`. It checks the committed
eight-line checksum manifest, provenance repository `avhn/secret`, signer workflow
`.github/workflows/release.yml`, source C, tag ref, certificate issuer and subject
name/digest before execution. The checkout is the bootstrap trust root; a matching
checksum alone is not independent provenance.

The verifier keeps `--repo avhn/secret`, `--source-digest C`,
`--signer-digest C`, `--source-ref refs/tags/v0.5.0`,
`--cert-oidc-issuer https://token.actions.githubusercontent.com`, the exact SAN
`--cert-identity https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.5.0`
and `--deny-self-hosted-runners`. Do not add `--signer-workflow`: gh 2.102.0
rejects it together with `--cert-identity`. The exact SAN already pins the
same-repository signer workflow and tag. Likewise, use `--repo`, not both
`--repo` and `--owner`, for verification or attestation download.

Cache location is `${XDG_CACHE_HOME:-$HOME/.cache}/secret/v0.5.0/`. Keep it on a
user-owned direct path with private directories (0700); `secret` is 0500 and
names-only `verified` metadata is 0600. Do not symlink cache or checksum paths.
The launchers resolve bounded entrypoint symlink chains and rehash before every
exec. They do not trust PATH binaries or silently fall back to Bash.

## Verify the complete release, including Desktop MCPB

From the independently authenticated checkout at C, acquire all eight payloads
and `checksums-v0.5.0.txt`, each initially into its own new empty directory, then
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
Then, from the authenticated v0.5.0 trusted release checkout, run:

```sh
sh scripts/install-release.sh --from-dir /absolute/private/release-input
# Once installed, this verifies the warm cache without downloading:
sh scripts/install-release.sh --offline
./bin/secret version
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
checking this path with the real verifier and a network witness. The v0.5.0 path
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

- `install.sh` exits 1 on argument, dependency, platform, verification, lock or
  publication failure; successful installation, no-op and help exit 0.
- `install.ps1` uses terminating errors. A failing file invocation exits nonzero;
  in-process iex callers should handle errors, not inspect a stale LASTEXITCODE.
- The POSIX pipeline reports the shell status, not necessarily curl's status.
  Empty or truncated downloads can therefore appear successful without installing.
  The function wrapper mitigates partial execution; download/review/run is stronger.
  The PowerShell pipeline changes no execution policy and propagates installer errors.

Doctor inspects explicit metadata only. A launcher/config/cache present on disk,
a matching supplied digest or a names-only `verified` file proves neither host
activation nor release provenance. It does not contact a host or repair stores.

## Migration from the staging name

After installing v0.5.0 or later, re-register MCP clients with the printed final
executable path and restart them. Once verified, manually remove only the
reviewed old `secret-go` / `secret-go.exe` installation. Windows users should
also remove the obsolete `%LOCALAPPDATA%\Programs\secret` user PATH entry if
nothing else uses it. Neither installer deletes old executables, removes old
PATH entries or edits client registrations. See [setup migration](setup.md#migrate-an-earlier-installation).

## Explicit Bash rollback

Invoke `/absolute/trusted/checkout/compat/secret` directly for the reviewed Bash
implementation, or explicitly point your own Unix CLI symlink at that path.
For example, after reviewing an existing symlink, replace only that link with
`ln -s /absolute/trusted/checkout/compat/secret ~/.local/bin/secret`. Do not
overwrite an unknown executable or a custom link. Windows Bash rollback requires
Git Bash and an explicit `bash /absolute/trusted/checkout/compat/secret` invocation;
it is not a native replacement executable. Never switch behavior automatically
on a Go failure. Existing Claude and Codex
manifests already reference `hooks/guard-secrets`. If you changed experimental
local configuration, restore the reviewed Bash config manually, restart the host
and review/re-trust Codex hooks. Compatibility CI pins the original Bash blob,
executable mode and interpreter and proves independence from a broken final launcher. No rollback procedure grants an
agent permission to retrieve values or install hooks into your real HOME.
