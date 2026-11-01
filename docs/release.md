# Release procedure

v0.4.0 adopts the final CLI name `secret`, Windows trusted store parents,
native Windows clip, Mute Agent branding and the opt-in release approval gate.
It is based on main after published v0.3.4 at checksum commit C `6ee3664`
(source S `5309977`). The v0.3.4 tag and `dist/checksums-v0.3.4.txt` are
immutable; that checksum file remains only at C on rel/v0.3.4, not in this tree.
The release retains six native CLI assets, pinned standalone installers,
a Desktop MCPB and official MCP Registry metadata. All four plugin/marketplace
versions become 0.4.0; the verified Go CLI launcher is `bin/secret` with explicit
byte-identical Bash rollback at `compat/secret`. Installed Bash hooks and their
configuration remain unchanged.
This release is not published yet. After publication main receives source S,
never C, so later pull requests keep a source HEAD. M4.1 Go activation remains
waiting sponsorship.
The binding contract is [the v0.3.0 plan, section 11](design/v0.3.0-plan.md#11-coordinator-decisions-and-frozen-interfaces-2026-10-28),
which supersedes the historical [M4 plan](design/m4-plan.md) only in its narrow
packaging/version scope. Consumer setup is in [setup.md](setup.md), with trust,
offline and rollback details in [install.md](install.md).

`v0.2.0` was tagged at `29216e7`, but its [tag workflow (run
39696575366)](https://github.com/avhn/secret/actions/runs/39696575366) failed before any
release assets, attestation or draft: checkout replaced the annotated tag with a
lightweight local ref. It is a dead, protected tag that must never be reused, moved or
deleted.

`v0.2.1` was tagged at `229ee0e` (full C
`229ee0ef5a229920f2bbe52f01adce1f7e0ae17c`), but its [tag workflow (run
39790612288)](https://github.com/avhn/secret/actions/runs/39790612288) failed in
`release-verify` after successful builds, byte reproduction and attestation:
gh rejects `--signer-workflow` together with `--cert-identity`. The installer
had the same conflict. This is another dead, protected tag, never to be reused,
moved or deleted. The owner-approved replacement identity was **0.2.2**.

`v0.2.2` was tagged at C `68b2cf8` (full C
`68b2cf8c5e9196f4d79afc032ea95b535751971d`, source S `3001f3c`). Its
[tag workflow (run 39876942544)](https://github.com/avhn/secret/actions/runs/39876942544)
passed every job through `release-verify`, but the owner retired the identity
before approving `release-publish`: a staged Go hook gap involving expansion
operands in arithmetic contexts, fixed by a later PR, led the owner not to
publish it. No draft or release exists. The tag ruleset keeps this dead tag;
never reuse, move or delete it. The subsequent v0.2.3 release completed that
replacement candidate/source/checksum cycle and was published on 2026-10-24;
its [M4 evidence](../ROADMAP.md#m4-releasable-linuxmacos-core) remains historical,
not evidence for the new v0.4.0 Windows/MCPB/Registry graph.

v0.3.0 was published on 2026-10-29 at checksum commit C `b911c92`; its tag
and `dist/checksums-v0.3.0.txt` are immutable. Registry run
[40816751048](https://github.com/avhn/secret/actions/runs/40816751048) was blocked
by the public Windows test install root under writable `RUNNER_TEMP` ancestors.
v0.3.1 changed those public test roots to fresh private user temp directories,
raised gh auth status to 60 seconds and fixed its PowerShell diagnostic category.

v0.3.1 was published on 2026-10-30 at checksum commit C `a2180875`; its tag
and `dist/checksums-v0.3.1.txt` are immutable. Registry run
[40967543855](https://github.com/avhn/secret/actions/runs/40967543855) was blocked
by the `current-user install owner` assertion. v0.3.2 sets the installed Windows
binary owner to the current user after atomic creation or replacement, including
when an elevated token or existing file supplies an Administrators owner.
v0.3.3 was published on 2026-10-30 at checksum commit C `ea85737`, together
with its MCP Registry record; its tag and `dist/checksums-v0.3.3.txt` are
immutable. It moved development and release builds to Go 1.27.3 without runtime
dependency changes or Go hook activation.

v0.3.4 was published on 2026-11-01 at checksum commit C `6ee3664` (source S
`5309977`), together with its active MCP Registry record. Its tag and
`dist/checksums-v0.3.4.txt` are immutable and remain on rel/v0.3.4; main was
promoted to S, never C. It added the Windows long-lived exec launcher without
changing run, Unix exec or the installed Bash CLI/hooks. All six public native
installs passed in Registry run
[41266742940](https://github.com/avhn/secret/actions/runs/41266742940).
All changed inputs require new gates; never reuse the v0.3.0, v0.3.1, v0.3.2,
v0.3.3 or v0.3.4 tags or assets.

## Approval boundaries

Local implementation and synthetic tests are reversible. Each outward action
requires separate explicit owner go-ahead: creating/pushing a release tag,
creating a draft GitHub Release, publishing it, promoting installation manifests
or the default installation branch, changing the default branch setting, and
publishing external package metadata such as a Homebrew formula. Permission for
one does not authorize the others. Do not commit, push, tag, dispatch model tests
or publish merely because this procedure describes how. Use signed lowercase
conventional commits, no co-author trailers, `git-safe-push` for an approved push
and `git-merge-safe` for an approved fast-forward.

The owner must configure the `release-publish` environment with a deployment
policy allowing only the `v0.4.0` tag before a tag can create a draft; the
workflow checks it. YAML cannot create or independently prove every repository
protection.

The owner approval gate (required reviewers on `release-publish` and
`registry-publish`) is **disabled** by owner decision while the owner is the only
user. To reactivate it, add the owner as required reviewer on both environments
and set the repository variable `SECRET_RELEASE_APPROVAL_GATE` to `enabled`; the
tag workflow then also requires the reviewer rule. Self-review is permitted
because a sole maintainer approves their own tag run, which keeps the draft a
separate human action. Protect `v*` tags with a ruleset
blocking deletion and updates. PR jobs have read-only permissions and never receive publishing or model
credentials. Only final-tag attestation gets OIDC/attestations write permission;
only approved draft creation gets contents write permission.

Configure both protected environments before their jobs run: `release-publish`
for draft creation, and `registry-publish` for official Registry metadata. Each
needs trusted tag/ref restrictions, plus required owner reviewers whenever the
approval gate is enabled (see above); YAML
references alone are not repository configuration evidence. Registry OIDC write
permission belongs only to the protected publishing job. Registry publication,
public native-install checks, installed-default promotion and tag/draft/release
actions remain separate owner checkpoints. No local test authorizes any of them.

## Packaging tools and advisory review

Artwork provenance and update instructions live in
[`resources/README.md`](../resources/README.md). The MCPB icon is copied from the
approved Mute Agent resources; its PNG is reviewed, committed bytes rendered from
the SVG, never regenerated in builds. Run
`python3 -I scripts/sync-branding.py --check` from the checkout root before
packaging to verify both icon copies match the approved sources.

Full assembly requires native macOS lipo, Go 1.27.3 (`GOTOOLCHAIN=local`),
Node 26.10.0, npm 11.19.1 and Python 3.14.8. Install the locked MCPB 2.1.2
validator with `npm ci --prefix packaging/mcpb --ignore-scripts`; no lifecycle
scripts or build tools ship in the bundle. The packaging driver verifies both
exact Mach-O slices and the Windows amd64 PE payload. ZIP entry order, modes,
timestamps and stored compression inputs are canonicalized for reproducibility.
The six raw CLI binaries remain separate release assets, including Windows arm64.

The reviewed build-only exception in `scripts/package_mcpb.py` retains Zod
3.25.76 for GHSA-mrhx-c7xc-m3w5: the advisory's affected `$ZodArray` /
`handleArrayResult` implementation and upstream fixes are v4-only; MCPB imports
v3 and the patched 4.6.6 is outside the declared dependency ranges. Only bounded,
reviewed local manifests enter validation. An offline reachability test rejects
any v4 load during real validation. This is not a general safety claim for Zod v3.
Exact overrides fix node-forge at 1.4.1 and tmp at 0.2.7; inspect the script
and lock for the full license/dependency rationale.

CI obtains fresh advisory data using `npm audit --prefix packaging/mcpb
--ignore-scripts --json` and preserves its exit status. Only status 0 or 1 may
reach `python3 -I scripts/package_mcpb.py --version 0.4.0 --audit-report
ABSOLUTE_AUDIT_JSON`; all other statuses fail. That check permits only the exact
reviewed advisory and its MCPB/zod-to-json-schema ancestors and reruns reachability.
Never suppress findings with `--omit=dev`, `--audit-level` or an unconditional
success fallback. A changed advisory graph needs review, not a larger allowlist.

Registry validation pins mcp-publisher v1.8.1 and its reviewed SHA-256 in
`scripts/release_manifest.py`. Downloads/extractions use separate new empty
directories and disposable HOME roots; scripts remain outside those directories
and Python readers use `-I`.

## 1. Two green integrated candidates, then source S

Finish every release lane before freezing S, including setup documentation. Keep
`hooks/hooks.json`, `hooks/guard-secrets`, both Codex hook configs
and `internal/hook` unchanged. The only installed-manifest change is the separately
approved equal version bump to 0.4.0, never Go hook activation or onFailure.
The separate owner-approved CLI-only extraction uses verified `bin/secret`,
byte-identical executable `compat/secret` and the `--stage cli-only` contract.
Standalone `secret[.exe]` replacement is verified and atomic, not a hook cutover. Keep the test-only
`.secret-release-test-fixture` marker out of the entire shipped tree; CI rejects
its tracked or on-disk presence, including symlinks.

Run two independently green integrated candidates on hosted runners. Required
coverage is retained CI (including native OS, provider, race, corpus and Bash 3.2),
independent reproducible release builds and native plugin installation/failure
matrices. PRs retain release/launcher/plugin and offline host classification suites, and
add `tests/test-install.sh`, native `tests/test-install.ps1`, `tests/test-mcpb.py`,
`tests/test-registry.py` and `tests/test-setup.py`. Select plugin `--stage cli-only`
explicitly: it checks version equality, the final Go CLI and unchanged Bash hooks, not M4.1. Native install
jobs record actual runner OS/image/architecture, not just cross-build success.
Candidate tests use disposable HOME/checkouts and candidate checksum metadata;
fixture bypass is never final provenance or an installation instruction.

`release-rehearsal` also runs on `pull_request` and `workflow_dispatch`, with
only `contents: read` and `attestations: read` and the ordinary `GITHUB_TOKEN`.
It checks out the PR head with full history and runs
`python3 -I scripts/rehearse-release.py` under a private TMPDIR. The script
explicitly fetches the dead annotated `v0.2.2` tag, requires its peel to be
`68b2cf8c5e9196f4d79afc032ea95b535751971d`, and creates a separate disposable
worktree. That worktree's own build scripts rebuild all four assets with Go
1.26.10 and compare against its committed `dist/checksums-v0.2.2.txt`.
Only after rebuilding, it copies the new verifier and installer into that scratch
worktree, mechanically substituting **only** `0.4.0` with `0.2.2`. This exercises
the same code with only the identity substituted; production scripts gain no
tag-override option and the protected tag is never moved or reused.

The rehearsal verifies all five genuine public subjects both online and with
bundles downloaded into fresh empty directories. It runs the production
non-fixture installer with `--from-dir`, a disposable HOME/cache and the trust
root obtained by `gh attestation trusted-root`, then repeats a cold offline
install with that retained root. A byte-flipped binary must fail both scripts;
a wrong C must fail the verifier, and wrong source-digest and tag-ref pins must
fail gh's genuine verification. The worktree and scratch are removed on exit.
This proves verifier/installer compatibility with existing public provenance,
not the new v0.4.0 tag workflow, new attestation issuance, publication, draft
round trip or native macOS installation. Those remain separate gates.

The model-using `host-hooks.yml` is manual only and inactive until sponsorship.
It is not a required M4 check. Its offline classification suite does not call
models and is required on PRs. Missing real host evidence is not a pass; it is
M4.1's explicit blocker. See [host evidence](design/host-failure-evidence.md).

Freeze the full source commit S only after applicable candidates pass. No docs,
hooks, source, versions, workflow or build inputs may change after S. Any such
change restarts candidate checks and S. Record evidence in PR/run records, not
post-S source edits.

## 2. Rebuild S and create checksum-only C

Current development and release builds use Go 1.27.3. The next release builds
with it, as did published v0.3.3. Published v0.2.x and v0.3.0 to v0.3.2 releases
remain reproducible with Go 1.26.10. Use each tag's own build inputs.

`release-build-a` and `release-build-b` use independent hosted macOS jobs, different
absolute checkout/output directories, isolated HOME/module/build caches, Go
1.27.3 and `GOTOOLCHAIN=local`. Build exactly with `CGO_ENABLED=0`, `GOAMD64=v1`,
`GOARM64=v8.0`, empty GOFLAGS, `SOURCE_DATE_EPOCH` equal to S's commit timestamp,
`-trimpath -buildvcs=false` and
`-ldflags='-buildid= -s -w -X main.version=0.4.0'`. The build script disables
persistent Go settings, workspaces and experiments. There is no `secretstub` tag.

```sh
# Trusted source checkout and an empty private output directory:
sh scripts/build-release.sh /absolute/private/build-output
sh scripts/verify-release.sh --checksums /absolute/private/build-output
```

`release-repro` byte-compares six raw Linux/macOS/Windows amd64/arm64
executables (Windows names end in .exe), `secret-v0.4.0-desktop.mcpb`, generated
`server.json` and the sorted eight-line `checksums-v0.4.0.txt`. No CLI archives.
Build the bundle first, then registry metadata from its final inspected bytes,
then checksums. No hashed payload embeds C, which would create a circular identity.
After owner authorization for the commit, commit only the generated
`dist/checksums-v0.4.0.txt` as signed checksum commit C', the direct child of S'.
The patch source S' already retains `dist/checksums-v0.3.0.txt`,
`dist/checksums-v0.3.1.txt` and `dist/checksums-v0.3.2.txt`; those historical files
are not current-version boundaries and must not change in S'..C'. The published
v0.3.3 and v0.3.4 checksum files remain at their respective C commits on
rel/v0.3.3 and rel/v0.3.4, not in this source tree.
`scripts/verify-release.sh --source` rejects every other S'..C' tree change and
markers in S' or C'. Rebuild at C' using the source commit's epoch; require equality
with the committed manifest. Never put a candidate manifest into a production checkout.

## 3. Immutable annotated tag at C

Creating and pushing `v0.4.0` requires explicit owner go-ahead. Verify its peeled
full SHA equals C, not S. Do not move or reuse the tag after failure. A changed
release input needs a new approved release identity and another candidate cycle.
The tag workflow repeats both builds, compares every byte/digest to C's committed
manifest and attests the eight payloads plus checksum asset. Candidate workflow
attestations, if any, cannot substitute for final-tag provenance.

Each tag-inspecting job explicitly fetches
`refs/tags/v0.4.0:refs/tags/v0.4.0` with `--no-tags --force` after checkout,
then requires an annotated object whose peeled commit equals `GITHUB_SHA`.
This restores only the runner's local ref, never the protected remote tag.
Checkout can otherwise replace the annotated tag with a lightweight ref even
with full history. Restore before calling any script that checks the tag.

## 4. Final-tag verification and draft

`release-attest` and `release-verify` run only for the repository's exact final
tag push. For each subject, require local SHA-256 equality and authenticated
repository, workflow, source C, tag ref and certificate issuer:

```sh
gh attestation verify /absolute/path/to/ASSET --repo avhn/secret \
  --source-digest FULL_C --signer-digest FULL_C --source-ref refs/tags/v0.4.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --cert-identity https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.4.0 \
  --deny-self-hosted-runners --format json
```

The exact SAN selects the signer workflow without `--signer-workflow`: gh
2.102.0 makes `--cert-identity`, `--cert-identity-regex`, `--signer-repo` and
`--signer-workflow` mutually exclusive. `--owner` and `--repo` are also mutually
exclusive for both verify and download. The verifier pins `--signer-digest FULL_C`
and the exact certificate SAN
`https://github.com/avhn/secret/.github/workflows/release.yml@refs/tags/v0.4.0`.
This is a same-repository workflow, not a reusable workflow; the composite
attestation action does not become the signer. On a tag push both source and
signer digests are C, and the source ref is the tag, not the default branch.
Moving signing into a reusable workflow would require its own signer SHA/ref.
The verifier additionally checks subject name/digest and all nine subjects.
Download bundles into new empty directories, keep readers/scripts elsewhere and
use Python `-I`. `release-verify` transports bundles under colon-free names;
`release-publish` restores gh's digest-named bundle files, re-verifies them and
creates a **draft only**, after environment review when the approval gate is enabled. Creating
that draft itself requires explicit owner go-ahead, not just tag permission.
The draft contains eight payloads, the checksum manifest and nine bundles named
`sha256-DIGEST.jsonl`. Portable release names avoid server-side normalization of
colons. The full verifier accepts portable names directly via `--bundle-dir`
and rejects ambiguous portable/colon copies. Only the Unix checkout installer's
`--from-dir` path needs a reviewed scratch copy in gh's `sha256:DIGEST.jsonl`
form; never create colon filenames on Windows.
Download every uploaded draft asset into a fresh empty directory, byte-compare
and verify provenance again. Do not run scripts from downloaded directories.

## 5. Publish, test public assets, then consider promotion

Publishing the verified draft requires another explicit owner go-ahead. The
workflow deliberately never runs `gh release edit --draft=false`. After approved
publication, `registry.yml` invokes reusable `plugin.yml` with exact `tag` and
`commit` inputs. A separately approved recovery can dispatch `plugin.yml` with
`published=true` at the exact v0.4.0 tag/C and complete tag history. Its native
matrix repeats installation from real public assets without a fixture bypass.
Unix checkout jobs validate cold/warm cache paths and actual offline provenance
with the cached executable removed and network attempts witnessed. Standalone
installers remain online-only; Windows cold offline installs are unsupported.
A digest or bundle alone is insufficient offline trust.

Only after final published checks are green may the owner separately authorize
promotion of main to source S, never checksum commit C. Keep C and its immutable
tag on the release branch; bringing C onto main breaks later candidate-source
checks. The CLI-only extraction does not activate Go hooks or change hook paths,
and a version bump does not authorize installed-default promotion. A default-branch
setting change or external package publication is another owner-approved action.
Do not alter S or C to record results; use GitHub run/release records and a later
tracking PR with links.

## 6. Public native evidence and Registry publication

The six candidate and public-install targets are ubuntu-latest amd64,
ubuntu-24.04-arm arm64, macos-15-intel amd64, macos-latest arm64,
windows-latest amd64 and windows-11-arm arm64. Record actual OS/image/CPU and
PE machine; cross-builds, emulation and synthetic installers do not replace
native runtime jobs. Runner unavailability blocks that release support claim.
Windows jobs retain both available native PowerShell editions, cmd invocation,
private ACLs, version, names-only synthetic MCP, redacted run, replacement and
failure preservation. M5a runtime CI remains mandatory.

The Desktop MCPB is validated with the locked CLI and native extracted-payload
smoke gates. Actual Desktop install, required user_config interpolation and
restart behavior are not host-tested in this release; never describe native
subprocess smoke as Desktop compatibility evidence. No Windows-on-Arm Desktop
or Linux Desktop bundle claim follows from CLI asset availability.

`registry.yml` starts only on the repository's published, non-draft,
non-prerelease v0.4.0 release (or exact tag/C manual recovery). It runs reusable
public native-install gates before protected `registry-publish` review. That
separate owner approval authorizes only Registry metadata publication.

The verified publication path is `python3 -I scripts/release_manifest.py
registry-publish --tag v0.4.0 --commit FULL_AUTHENTICATED_C`. It rechecks the
annotated tag and checksum-only S..C boundary; downloads the eighteen public
assets into fresh directories; verifies all nine attested subjects and committed
checksums; inspects the bundle; regenerates metadata/checksums and byte-compares
them; and validates the absolute `server.json` with the pinned publisher.
It then uses `mcp-publisher login github-oidc`, never a stored registry token,
and publishes that exact downloaded metadata. This is workflow procedure, not
permission to invoke publication from a development shell.

The name is `io.github.avhn/secret`, package version 0.4.0, stdio only. The MCPB
URL is version-pinned and `fileSha256` derives from its final bytes. An identical
already-active identity/version/packages record is accepted on rerun; conflicts
fail. A bounded official API check must confirm the exact active record. Failure
leaves the GitHub release intact and Registry status incomplete. Never replace
assets, retag, regenerate replacement public bytes or promote defaults to recover.
Record final evidence outside S/C, then in a later tracking PR.

## M4.1 follow-up, not v0.4.0 publication work

Before any Claude hook activation, sponsors must fund model use and the
owner must provision the protected `host-hook-tests` environment and applicable
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` secrets without exposing values. Only then
may the owner enable `vars.SECRET_HOST_TESTS == 'enabled'` and dispatch trusted
refs. Missing auth/model availability or absent healthy-control witnesses leaves
the gate incomplete. Pins start at Claude Code 2.1.295 and Codex 0.163.0; host
upgrades need new evidence. Codex stays on Bash regardless of Claude results.

M4.1 stages and tests its separately reviewed release manifests, both Claude `onFailure: "block"`
entries pointing to `guard-go` and neutral-output/error behavior in
`internal/hook`. Enable `tests/test-plugin.py --stage m4.1` there, not in the v0.4.0
workflow. The harness requires that staged configuration on a disposable hosted
branch. Changed inputs require new source/candidate/release identity and renewed
owner approvals, never mutation of the M4 S, C or immutable v0.3.0/v0.3.1/v0.3.2/v0.3.3/v0.3.4 tags.
