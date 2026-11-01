# Contributing

## Set up

Clone the repository and use Bash 3.2 or newer, Perl, jq, Python 3, ripgrep and ShellCheck for the current shell suites. The Go module requires Go 1.27.3 or newer; CI pins Go 1.27.3 with `GOTOOLCHAIN=local` for all checks, including bounded fuzzing. Provider integration needs an isolated Linux Secret Service session or a disposable macOS Keychain. Never run tests against your normal credential stores.

## Test locally

```bash
bash tests/test-secret.sh    # CLI; Perl, Python 3 and ripgrep
bash tests/test-backends.sh  # disposable provider stub
bash tests/test-guard.sh     # Claude Code guard; jq
bash tests/test-codex.sh     # Codex guard
shellcheck compat/secret bin/secret hooks/guard-secrets tests/*.sh
```

The four CLI/provider suites also accept `SECRET_CLI=/absolute/path/to/secret` to run an alternate executable instead of `compat/secret`. Build a regular Go CLI for `secret`, `libsecret` and `keychain`, and a separate `go build -tags secretstub` executable for `backends`. The tag enables the disposable directory provider only in that test binary; the default build ignores `SECRET_BACKEND_STUB_DIR`. `bash tests/go-cli.sh SUITE /absolute/path/to/binary` compares every case with `testdata/inventory/go-expected-divergence.tsv`: listed failures must still fail and unlisted cases must pass. The current `deliberate` entries cover Bash-specific Perl fault injection, not Go filter tests; Go filter failure and signal injection are covered in `internal/cli/supervise_test.go`. Do not add values to diagnostics or argv.

The Claude and Codex guard suites also accept `SECRET_GUARD='/absolute/path/to/secret hook claude'` and `SECRET_GUARD='/absolute/path/to/secret hook codex'` respectively. Run `bash tests/go-hook.sh guard /absolute/path/to/secret claude` and `bash tests/go-hook.sh codex /absolute/path/to/secret codex` to require exact case outcomes from `testdata/inventory/go-hook-divergence.tsv`. The listed `pending-M2-ast` shell cases are not yet protected by Go; the Bash guard remains installed. Malformed-call denials are recorded in [hook tightening decisions](docs/design/hook-tightening.md). Do not broaden a divergence list without classifying the cause.

In isolated provider environments, run `SECRET_REQUIRE_LIBSECRET=1 bash tests/test-libsecret.sh` on Linux and `SECRET_REQUIRE_KEYCHAIN=1 bash tests/test-keychain.sh` on macOS. These suites use synthetic fixtures; CI provides the required isolation. Run the Go versions only on the corresponding isolated CI runners, never against a normal keyring or Keychain. For Go changes, check `gofmt -l .`, `go vet ./...` and `go test ./...`; CI also runs `go test -race ./...`, a `go mod tidy` diff check and cross-compilation. The macOS CI matrix also tests stock Bash 3.2.

## M3 operator and metadata tests

M3 passed its hosted CI gate (PR #8) and is implemented in the staged Go CLI,
not in the retained Bash `compat/secret`.
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
go build -o "$build_dir/secret" ./cmd/secret
python3 -I tests/test-operator.py "$build_dir/secret"
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

Ubuntu CI runs each feature fuzz target with Go 1.27.3 and a bounded budget:

```bash
for target in FuzzMetadataSelection FuzzPrivateImporterJSON FuzzMCPProtocol; do
  go test ./internal/feature -run '^$' -fuzz "^$target$" -fuzztime=15s -parallel=2
done
```

Use the same Go 1.27.3 toolchain and `GOTOOLCHAIN=local` for fuzzing, builds,
vet, ordinary tests, race tests and release builds. Do not retry or filter
fuzz failures. Published releases remain reproducible with Go 1.26.10 from
their tags; the historical release rehearsal retains that toolchain.

Keep JSON metadata names-only, audit opt-in and MCP explicitly allowlisted. The M2 guard
still conservatively denies new secret subcommands; do not relax it for tests.
Hosted PTY/provider results, native OS tests and all prior shell, Bash 3.2,
inventory, exact hook and race gates are required before calling M3 complete.

## M5e PowerShell oracle tests (Windows only)

Production PowerShell classification remains disabled. These tests use synthetic
source, parse and statically bind without execution, and exercise a Windows-only
test adapter through the full Go hook. They do not install hooks, invoke models,
access credential providers or prove real-host failure blocking.

Use Go 1.27.3 with `GOTOOLCHAIN=local`. From the checkout on Windows, invoke the
committed driver under each tested executable, not an arbitrary `pwsh` on PATH:

```powershell
$env:GOTOOLCHAIN = 'local'
$desktop = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
& $desktop -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ./tests/test-powershell.ps1 -Edition Desktop -Oracle $desktop
if ($LASTEXITCODE -ne 0) { throw 'Desktop oracle failed' }
# Download the official 7.6.7 x64 zip into a new empty directory, verify its
# pinned SHA-256, then extract into another new empty directory. See the fixture
# README and ci.yml for the exact URL, digest and verification commands.
$core = 'C:\absolute\disposable\PowerShell-7.6.7\pwsh.exe'
& $core -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ./tests/test-powershell.ps1 -Edition Core -Oracle $core
if ($LASTEXITCODE -ne 0) { throw 'Core oracle failed' }
```

The driver asserts Desktop 5.1 or exactly Core 7.6.7 and verifies its own executable
matches the oracle path. It runs the Go tests without building or installing a CLI.
Both edition lanes are required in CI, record the runner image/full versions and
fail on missing or broken oracles. On other systems the native tests skip unless
`SECRET_PS_ORACLE` is set; `SECRET_PS_ORACLE_REQUIRED=1` forbids that skip.

The differential pass uses a fixed seed and 2,000 mutations per edition. Optional
`SECRET_PS_ORACLE_BUDGET` changes the local generation count, not the required CI
budget. Persist any printed minimized synthetic counterexample in
`testdata/hook/powershell/replay.jsonl` before fixing a mismatch. Replay is always
loaded alongside the corpus. The runner sends bounded batches of up to 250
sources per fresh no-profile process, with indexed projections/errors and strict
count, order and field checks. See the fixture README for protocol and capture/
watchdog bounds; no hook deadline or CI generation budget changes. Oracle fault
tests run without PowerShell. Native logs include classifier p99 and worst-case
40 KiB timing, public/protected path controls, symlink availability and 8.3 support
on the named fixture volume. Keep all prior Go, Windows, shell
and inventory gates. See the [pins and evidence contract](testdata/hook/powershell/README.md)
and [M5e plan](docs/design/m5e-plan.md); passing parser CI does not finish M5e.

## M5d encrypted-store tests

Use Go 1.27.3 with `GOTOOLCHAIN=local`, including bounded fuzzing. Review
the exact age pin, complete module graph, every new license, checksums and
reachable vulnerability scan before any
dependency change. See [the binding M5d plan](docs/design/m5d-plan.md) and
[age guarantees and recovery](docs/age.md). Core age imports only, never a crypto
subprocess. Keep plaintext and identity material in owned byte buffers; never
print it or put it in argv, diagnostics, audit or JSON.

```bash
go mod verify
go mod tidy -diff
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
go test ./internal/store -run '^$' -fuzz '^FuzzAgeEnvelope$' -fuzztime=15s -parallel=2
go test ./internal/backend -run '^$' -fuzz '^FuzzAgeDecrypt$' -fuzztime=15s -parallel=2
go test ./internal/backend -run '^$' -fuzz '^FuzzAgeKeyFiles$' -fuzztime=15s -parallel=2
python3 -I tests/test-age.py /absolute/fresh/secret
```

Each fuzz invocation runs one target only. The PTY/crash suite builds a test-only
fixture generator and creates identities independently for every test, writing
them directly under disposable HOME roots. No private keys belong in corpus
files or fixtures. Tests cover ciphertext-only persistence, exact consent,
create-only init, authenticated source selection drift, rekey, private paths,
full-stream authentication, injected publication failures and killed writers
whose tokened locks are never stolen. Windows runs codec tests and asserts age
filesystem rejection before access; native Linux/macOS PTYs remain required.
Keep all previous Go, race, shell, provider, Bash 3.2 and exact inventory gates.
M5d passed its hosted gate in PR #28; changed inputs still require the applicable
hosted jobs. Local tests alone do not establish new native or release evidence.

## M4 release, launcher and offline host tests

M4's v0.2.3 release is complete. The v0.3.4 extension changes packaging and
keeps all four manifests at 0.3.4. The owner-approved CLI-only extraction puts
the verified launcher at `bin/secret`, retaining Bash at `compat/secret`.
Claude/Codex hooks remain Bash. M4.1 still owns `onFailure: "block"`, `guard-go`
activation and Go hook output-contract changes, waiting sponsorship. See [the release plan](docs/design/v0.3.0-plan.md),
[installation](docs/install.md) and [release approvals](docs/release.md).

New production files are `scripts/build-release.sh`, `scripts/verify-release.sh`,
`scripts/install-release.sh`, `hooks/guard-go` and `bin/secret`. New workflows
are `release.yml`, `plugin.yml` and inactive `host-hooks.yml`. Synthetic fixtures
live in `testdata/plugin/` and `testdata/host-hooks/`; `tests/host-hook-fixture.go`
is test-only under `-tags hosthookfixture`, never a shipped binary.

Use exactly Go 1.27.3, matching GOROOT/PATH and `GOTOOLCHAIN=local` for release
builds. Complete assembly also requires native macOS lipo, Node 26.10.0,
npm 11.19.1, Python 3.14.8 and the locked MCPB 2.1.2 validator. Install it with
`npm ci --prefix packaging/mcpb --ignore-scripts`. Review the narrowly bounded
Zod advisory exception in `scripts/package_mcpb.py` and the
[fresh-audit policy](docs/release.md#packaging-tools-and-advisory-review);
never suppress unrelated findings or lifecycle-script safeguards.
Run tests from the trusted checkout, keeping downloads in fresh empty
directories and readers/scripts outside them. Never install into your real HOME.

```bash
export GOTOOLCHAIN=local
python3 -I tests/test-release.py
bash tests/test-launchers.sh
bash tests/test-install.sh
python3 -I tests/test-mcpb.py
python3 -I tests/test-registry.py
python3 -I tests/test-setup.py
# Full assembly requires macOS/lipo and the pinned packaging tools above:
assets="$(mktemp -d)"
sh scripts/build-release.sh "$assets"
python3 -I tests/test-plugin.py "$PWD" "$assets" --stage cli-only --manifest-only
python3 -I tests/test-plugin.py "$PWD" "$assets" --stage cli-only
python3 -I tests/test-host-hooks.py # offline classification, no model calls
shellcheck compat/secret bin/secret hooks/guard-secrets hooks/guard-go install.sh scripts/*.sh tests/*.sh
# On macOS, also run retained shell suites with stock Bash 3.2:
/bin/bash tests/test-launchers.sh
/bin/bash tests/test-install.sh
```

On disposable native Windows hosts, run the installer suite in each available
PowerShell edition (5.1 and 7), never against the real user install or PATH:

```powershell
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File tests/test-install.ps1
pwsh -NoProfile -NonInteractive -File tests/test-install.ps1
```

The installer suites use synthetic transport/verifier fixtures; setup tests parse
all fenced JSON/TOML/CLI examples, verify argv against the Go CLI source and
exercise synthetic shell launchers with disposable HOME/TMPDIR, no network or
real stores. Windows escaping is checked as data in the Python
suite, not native client evidence. MCPB tests require the locked validator and
Go cache; Registry tests are offline and never publish. None starts a model or
proves Desktop install/interpolation/restart behavior.

CI runs independent macOS full assembly plus native Linux/macOS/Windows
amd64/arm64 candidate and public-install jobs. Release workflows explicitly use
`--stage cli-only`, the final Go CLI plus unchanged Bash hook contract.
The test default is `cli-only`; `--stage m4.1` preserves the stronger
activation assertions for that milestone. Do not use it as a v0.3.4 gate or
weaken other assertions. Tests assert
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
