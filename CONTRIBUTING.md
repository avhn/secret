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

M3 is implemented in the staged Go CLI, pending hosted CI, not in `bin/secret`.
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

## Propose changes

Work on a branch and open a pull request. Include focused table-driven tests in the same commit as behavior changes. A useful guard test supplies a synthetic tool envelope, a disposable filesystem layout and a precise expected allow/deny decision, including relevant stderr or exit status; test both the protected path and a nearby safe case. If an expectation changes, classify and explain the security reason rather than quietly weakening it. Update [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md) and relevant docs in the same PR.

GitHub Actions is the gate: open a PR to run the Ubuntu and macOS shell and provider jobs, plus the Go job on Ubuntu, macOS and Windows. Wait for all applicable runner checks to pass before merging; local checks alone are not sufficient. Use signed, lowercase conventional commits (`type(scope): summary`), no co-author trailers, no em or en dashes, and no emojis.

## Security and licensing

Report suspected value leaks via [GitHub private vulnerability reporting](SECURITY.md#reporting), not a public issue or PR. Reproduce with synthetic values only; never include live credentials. This project is [GPL-3.0-or-later licensed](LICENSE). Contributions are submitted under GPL-3.0-or-later; no CLA is required. See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
