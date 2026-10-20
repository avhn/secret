# Contributing

## Set up

Clone the repository and use Bash 3.2 or newer, Perl, jq, Python 3, ripgrep and ShellCheck for the current shell suites. The Go module requires Go 1.26.0 or newer; CI pins Go 1.26.0. Provider integration needs an isolated Linux Secret Service session or a disposable macOS Keychain. Never run tests against your normal credential stores.

## Test locally

```bash
bash tests/test-secret.sh    # CLI; Perl, Python 3 and ripgrep
bash tests/test-backends.sh  # disposable provider stub
bash tests/test-guard.sh     # Claude Code guard; jq
bash tests/test-codex.sh     # Codex guard
shellcheck bin/secret hooks/guard-secrets tests/*.sh
```

The four CLI/provider suites also accept `SECRET_CLI=/absolute/path/to/secret` to run an alternate executable instead of `bin/secret`. Build a regular Go CLI for `secret`, `libsecret` and `keychain`, and a separate `go build -tags secretstub` executable for `backends`. The tag enables the disposable directory provider only in that test binary; the default build ignores `SECRET_BACKEND_STUB_DIR`. `bash tests/go-cli.sh SUITE /absolute/path/to/binary` compares every case with `testdata/inventory/go-expected-divergence.tsv`: listed failures must still fail and unlisted cases must pass. The current `deliberate` entries cover Bash-specific Perl fault injection, not Go filter tests; Go filter failure and signal injection are covered in `internal/cli/supervise_test.go`. Do not add values to diagnostics or argv.

The Claude and Codex guard suites also accept `SECRET_GUARD='/absolute/path/to/secret hook claude'` and `SECRET_GUARD='/absolute/path/to/secret hook codex'` respectively. Run `bash tests/go-hook.sh guard /absolute/path/to/secret claude` and `bash tests/go-hook.sh codex /absolute/path/to/secret codex` to require exact case outcomes from `testdata/inventory/go-hook-divergence.tsv`. The listed `pending-M2-ast` shell cases are not yet protected by Go; the Bash guard remains installed. Malformed-call denials are recorded in [hook tightening decisions](docs/design/hook-tightening.md). Do not broaden a divergence list without classifying the cause.

In isolated provider environments, run `SECRET_REQUIRE_LIBSECRET=1 bash tests/test-libsecret.sh` on Linux and `SECRET_REQUIRE_KEYCHAIN=1 bash tests/test-keychain.sh` on macOS. These suites use synthetic fixtures; CI provides the required isolation. Run the Go versions only on the corresponding isolated CI runners, never against a normal keyring or Keychain. For Go changes, check `gofmt -l .`, `go vet ./...` and `go test ./...`; CI also runs `go test -race ./...`, a `go mod tidy` diff check and cross-compilation. The macOS CI matrix also tests stock Bash 3.2.

## M3 operator and metadata tests

M3 passed its hosted CI gate (PR #8) and is implemented in the staged Go CLI,
not in the installed Bash `bin/secret`.
Use disposable synthetic files and HOME directories; never use an actual store.

```bash
gofmt -l .
go build ./...
go vet ./...
GOOS=windows go vet ./...
GOOS=darwin go vet ./...
go test -count=1 ./...
go test -race ./internal/...
go test ./internal/cli ./internal/feature ./internal/secure ./internal/backend ./internal/store
build_dir="$(mktemp -d)"
go build -o "$build_dir/secret-go" ./cmd/secret
python3 -I tests/test-operator.py "$build_dir/secret-go"
```

The Unix PTY suite covers exact consent, hidden bounded value entry, cancellation,
terminal restoration, lifecycle/import, JSON, MCP allowlisting and template cleanup
on normal and catchable-signal exits. It skips cleanly where PTYs are unavailable.
It never installs hooks or contacts providers. Mock provider and transaction tests
run in the ordinary Go suite; real operator tests are platform-scoped and skip
unless their required-provider environment gate is explicitly enabled.

Only on the corresponding isolated GitHub runners, run
`SECRET_REQUIRE_LIBSECRET=1 go test -v ./internal/backend -run '^(TestLibsecretIntegration|TestOperatorLibsecretIntegration)$' -count=1`
or
`SECRET_REQUIRE_KEYCHAIN=1 go test -v ./internal/backend -run '^(TestKeychainIntegration|TestOperatorKeychainIntegration)$' -count=1`.
The Linux test starts a private D-Bus session with a disposable HOME/keyring; the
macOS test selects a disposable explicit keychain without changing the default or
search list. Required dependencies or provider failures fail the enabled gate.
Operator tests exercise import/export, collision-before-fetch, fresh-account
rotation/rename/delete, exact cleanup and provider-boundary argv sampling with
synthetic sentinels. Do not enable these gates locally.

Ubuntu CI runs each feature fuzz target with a bounded budget, for example
`go test ./internal/feature -run '^$' -fuzz '^FuzzMetadataSelection$' -fuzztime=15s -parallel=2`.
The other targets are `FuzzPrivateImporterJSON` and `FuzzMCPProtocol`. Keep JSON
metadata names-only, audit opt-in and MCP explicitly allowlisted. The M2 guard
still conservatively denies new secret subcommands; do not relax it for tests.
Hosted PTY/provider results, native OS tests and all prior shell, Bash 3.2,
inventory, exact hook and race gates are required before calling M3 complete.

## M4 release, launcher and offline host tests

M4 prepares opt-in release tooling; the installed Bash CLI, Claude/Codex hooks
and four manifest versions remain unchanged. M4.1 owns all version bumps,
`onFailure: "block"`, `guard-go` activation, the `bin/secret`/`compat/secret`
switch and Go hook output-contract changes. See [the M4 plan](docs/design/m4-plan.md),
[installation](docs/install.md) and [release approvals](docs/release.md).

New production files are `scripts/build-release.sh`, `scripts/verify-release.sh`,
`scripts/install-release.sh`, `hooks/guard-go` and `bin/secret-go`. New workflows
are `release.yml`, `plugin.yml` and inactive `host-hooks.yml`. Synthetic fixtures
live in `testdata/plugin/` and `testdata/host-hooks/`; `tests/host-hook-fixture.go`
is test-only under `-tags hosthookfixture`, never a shipped binary.

Use exactly Go 1.26.0, matching GOROOT/PATH and `GOTOOLCHAIN=local` for release
builds. Run tests from the trusted checkout, keeping downloads in fresh empty
directories and readers/scripts outside them. Never install into your real HOME.

```bash
export GOTOOLCHAIN=local
python3 -I tests/test-release.py
bash tests/test-launchers.sh
assets="$(mktemp -d)"
sh scripts/build-release.sh "$assets"
python3 -I tests/test-plugin.py "$PWD" "$assets" --manifest-only
python3 -I tests/test-plugin.py "$PWD" "$assets"
python3 -I tests/test-host-hooks.py # offline classification, no model calls
shellcheck bin/secret bin/secret-go hooks/guard-secrets hooks/guard-go scripts/*.sh tests/*.sh
# On macOS, also run the launcher suite with stock Bash 3.2:
/bin/bash tests/test-launchers.sh
```

CI runs independent release builds and native Linux/macOS amd64/arm64 install
jobs. `plugin-manifest-check` uses the default M4 shipped-state contract.
`--stage m4.1` preserves the stronger activation assertions for that milestone;
do not enable it on the M4 workflow or weaken other assertions. Tests assert
statuses, JSON and filesystem execution witnesses, not diagnostics alone.
`.secret-release-test-fixture` is forbidden in the shipped tree, S and C,
including dangling symlinks. Only disposable synthetic checkout copies may use
it with `SECRET_RELEASE_TEST_ROOT`; environment alone must never bypass trust.

The real-host harness is inactive pending sponsorship, not an M4 required check.
`python3 -I tests/test-host-hooks.py` runs offline tests without credentials or
models. To include test-only compiled faults, build
`go build -tags hosthookfixture -o ABSOLUTE_FIXTURE tests/host-hook-fixture.go`
and pass `--fixture ABSOLUTE_FIXTURE`. See
[host evidence](docs/design/host-failure-evidence.md) for pins and spend limits.
Owner-approved activation requires protected `host-hook-tests` reviewers and
trusted refs, `vars.SECRET_HOST_TESTS == 'enabled'`, and applicable
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` environment secrets provisioned by the owner.
Only then dispatch trusted refs manually; never add model calls to PR checks.
Missing auth, absent healthy controls or model outages leave M4.1 incomplete.

Creating/pushing tags, creating release drafts, publishing releases, promoting
installed defaults/manifests, changing default branches and publishing external
package metadata each require separate explicit owner go-ahead. No successful
local check, workflow or earlier approval authorizes those outward actions.

## Propose changes

Work on a branch and open a pull request. Include focused table-driven tests in the same commit as behavior changes. A useful guard test supplies a synthetic tool envelope, a disposable filesystem layout and a precise expected allow/deny decision, including relevant stderr or exit status; test both the protected path and a nearby safe case. If an expectation changes, classify and explain the security reason rather than quietly weakening it. Update [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md) and relevant docs in the same PR.

GitHub Actions is the gate: open a PR to run the Ubuntu and macOS shell and provider jobs, plus the Go job on Ubuntu, macOS and Windows. Wait for all applicable runner checks to pass before merging; local checks alone are not sufficient. Use signed, lowercase conventional commits (`type(scope): summary`), no co-author trailers, no em or en dashes, and no emojis.

## Security and licensing

Report suspected value leaks via [GitHub private vulnerability reporting](SECURITY.md#reporting), not a public issue or PR. Reproduce with synthetic values only; never include live credentials. This project is [GPL-3.0-or-later licensed](LICENSE). Contributions are submitted under GPL-3.0-or-later; no CLA is required. See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
