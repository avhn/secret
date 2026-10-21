# Release procedure

M4 prepares the Linux/macOS core release V=0.2.0 without changing installed Bash
CLI/hooks or any of the four plugin/marketplace versions. M4.1 owns all activation
changes and is blocked on sponsorship for model usage. The full frozen contract
is in [the M4 plan](design/m4-plan.md); consumer dependencies and failure recovery
are in [install.md](install.md).

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

The owner must configure the `release-publish` environment with at least one
required reviewer and a deployment policy allowing only the `v0.2.0` tag before
a tag can create a draft. The workflow checks both settings; YAML cannot create
or independently prove every repository protection. Self-review is permitted
because a sole maintainer must approve their own tag run; the reviewer gate
still keeps the draft a separate human action. Protect `v*` tags with a ruleset
blocking deletion and updates. PR jobs have read-only permissions and never receive publishing or model
credentials. Only final-tag attestation gets OIDC/attestations write permission;
only approved draft creation gets contents write permission.

## 1. Two green integrated candidates, then source S

Finish all M4 source, workflow and documentation changes before freezing S. Keep
`bin/secret`, `hooks/hooks.json`, `hooks/guard-secrets`, all four installed
manifests and `internal/hook` unchanged. Keep the test-only
`.secret-release-test-fixture` marker out of the entire shipped tree; CI rejects
its tracked or on-disk presence, including symlinks.

Run two independently green integrated candidates on hosted runners. Required
coverage is retained CI (including native OS, provider, race, corpus and Bash 3.2),
independent reproducible release builds and native plugin installation/failure
matrices. PRs run `tests/test-release.py`, `tests/test-launchers.sh`,
`tests/test-plugin.py` and offline `tests/test-host-hooks.py`. Native install
jobs record actual runner OS/image/architecture, not just cross-build success.
Candidate tests use disposable HOME/checkouts and candidate checksum metadata;
fixture bypass is never final provenance or an installation instruction.

The model-using `host-hooks.yml` is manual only and inactive until sponsorship.
It is not a required M4 check. Its offline classification suite does not call
models and is required on PRs. Missing real host evidence is not a pass; it is
M4.1's explicit blocker. See [host evidence](design/host-failure-evidence.md).

Freeze the full source commit S only after applicable candidates pass. No docs,
hooks, source, versions, workflow or build inputs may change after S. Any such
change restarts candidate checks and S. Record evidence in PR/run records, not
post-S source edits.

## 2. Rebuild S and create checksum-only C

`release-build-a` and `release-build-b` use independent hosted jobs, different
absolute checkout/output directories, isolated HOME/module/build caches, Go
1.26.0 and `GOTOOLCHAIN=local`. Build exactly with `CGO_ENABLED=0`, `GOAMD64=v1`,
`GOARM64=v8.0`, empty GOFLAGS, `SOURCE_DATE_EPOCH` equal to S's commit timestamp,
`-trimpath -buildvcs=false` and
`-ldflags='-buildid= -s -w -X main.version=0.2.0'`. The build script disables
persistent Go settings, workspaces and experiments. There is no `secretstub` tag.

```sh
# Trusted source checkout and an empty private output directory:
sh scripts/build-release.sh /absolute/private/build-output
sh scripts/verify-release.sh --checksums /absolute/private/build-output
```

`release-repro` byte-compares all four raw linux/darwin amd64/arm64 executables
and the sorted four-line `checksums-v0.2.0.txt`. No Windows assets or archives.
After owner authorization for the commit, commit only the generated
`dist/checksums-v0.2.0.txt` as signed checksum commit C, the direct child of S.
`scripts/verify-release.sh --source` rejects every other S..C tree change and
markers in S or C. Rebuild at C using S's epoch; require equality with the
committed manifest. Never put a candidate manifest into a production checkout.

## 3. Immutable annotated tag at C

Creating and pushing `v0.2.0` requires explicit owner go-ahead. Verify its peeled
full SHA equals C, not S. Do not move or reuse the tag after failure. A changed
release input needs a new approved release identity and another candidate cycle.
The tag workflow repeats both builds, compares every byte/digest to C's committed
manifest and attests the four assets plus checksum asset. Candidate workflow
attestations, if any, cannot substitute for final-tag provenance.

## 4. Final-tag verification and draft

`release-attest` and `release-verify` run only for the repository's exact final
tag push. For each subject, require local SHA-256 equality and authenticated
repository, workflow, source C, tag ref and certificate issuer:

```sh
gh attestation verify /absolute/path/to/ASSET --repo avhn/secret \
  --signer-workflow avhn/secret/.github/workflows/release.yml \
  --source-digest FULL_C --source-ref refs/tags/v0.2.0 \
  --cert-oidc-issuer https://token.actions.githubusercontent.com
```

The verifier additionally checks subject name/digest and all five subjects.
Download bundles into new empty directories, keep readers/scripts elsewhere and
use Python `-I`. `release-verify` transports bundles under colon-free names;
`release-publish` restores gh's digest-named bundle files, re-verifies them and
creates a **draft only**, after separately approved environment review. Creating
that draft itself requires explicit owner go-ahead, not just tag permission.
The draft contains four binaries, the checksum manifest and five bundles.
Download every uploaded draft asset into a fresh empty directory, byte-compare
and verify provenance again. Do not run scripts from downloaded directories.

## 5. Publish, test public assets, then consider promotion

Publishing the verified draft requires another explicit owner go-ahead. The
workflow deliberately never runs `gh release edit --draft=false`. After approved
publication, dispatch `plugin.yml` with `published=true` at exactly full C with
complete tag history. Its native matrix repeats the install from the real public
assets without the fixture bypass, validates cold/warm paths and checks actual
offline provenance with the cached executable removed and network attempts
witnessed. A digest or bundle alone is insufficient offline trust.

Only after final published checks are green may the owner separately authorize
promotion of the M4 branch to exactly C. This does not activate Go, change hook
paths, bump plugin versions or create `compat/secret`. A default-branch setting
change or external package publication is yet another owner-approved action.
Do not alter C to record results; use GitHub run/release records and a later
tracking PR to mark M4 complete with links.

## M4.1 follow-up, not M4 publication work

Before any Claude/default CLI activation, sponsors must fund model use and the
owner must provision the protected `host-hook-tests` environment and applicable
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` secrets without exposing values. Only then
may the owner enable `vars.SECRET_HOST_TESTS == 'enabled'` and dispatch trusted
refs. Missing auth/model availability or absent healthy-control witnesses leaves
the gate incomplete. Pins start at Claude Code 2.1.295 and Codex 0.163.0; host
upgrades need new evidence. Codex stays on Bash regardless of Claude results.

M4.1 stages and tests the four 0.2.0 manifests, both Claude `onFailure: "block"`
entries pointing to `guard-go`, the verified `bin/secret` launcher with
byte-identical executable `compat/secret`, and neutral-output/error behavior in
`internal/hook`. Enable `tests/test-plugin.py --stage m4.1` there, not in M4's
workflow. The harness requires that staged configuration on a disposable hosted
branch. Changed inputs require new source/candidate/release identity and renewed
owner approvals, never mutation of the M4 S, C or immutable v0.2.0 tag.
