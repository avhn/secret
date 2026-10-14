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

## Propose changes

Work on a branch and open a pull request. Include focused table-driven tests in the same commit as behavior changes. A useful guard test supplies a synthetic tool envelope, a disposable filesystem layout and a precise expected allow/deny decision, including relevant stderr or exit status; test both the protected path and a nearby safe case. If an expectation changes, classify and explain the security reason rather than quietly weakening it. Update [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md) and relevant docs in the same PR.

GitHub Actions is the gate: open a PR to run the Ubuntu and macOS shell and provider jobs, plus the Go job on Ubuntu, macOS and Windows. Wait for all applicable runner checks to pass before merging; local checks alone are not sufficient. Use signed, lowercase conventional commits (`type(scope): summary`), no co-author trailers, no em or en dashes, and no emojis.

## Security and licensing

Report suspected value leaks via [GitHub private vulnerability reporting](SECURITY.md#reporting), not a public issue or PR. Reproduce with synthetic values only; never include live credentials. This project is [MIT licensed](LICENSE). Contributions are submitted under MIT; no CLA is required. See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
