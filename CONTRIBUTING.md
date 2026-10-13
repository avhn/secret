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

In isolated provider environments, run `SECRET_REQUIRE_LIBSECRET=1 bash tests/test-libsecret.sh` on Linux and `SECRET_REQUIRE_KEYCHAIN=1 bash tests/test-keychain.sh` on macOS. These suites use synthetic fixtures; CI provides the required isolation. For Go changes, check `gofmt -l .`, `go vet ./...` and `go test ./...`; CI also runs `go test -race ./...`, a `go mod tidy` diff check and cross-compilation. The macOS CI matrix also tests stock Bash 3.2.

## Propose changes

Work on a branch and open a pull request. Include focused table-driven tests in the same commit as behavior changes. A useful guard test supplies a synthetic tool envelope, a disposable filesystem layout and a precise expected allow/deny decision, including relevant stderr or exit status; test both the protected path and a nearby safe case. If an expectation changes, classify and explain the security reason rather than quietly weakening it. Update [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md) and relevant docs in the same PR.

GitHub Actions is the gate: open a PR to run the Ubuntu and macOS shell and provider jobs, plus the Go job on Ubuntu, macOS and Windows. Wait for all applicable runner checks to pass before merging; local checks alone are not sufficient. Use signed, lowercase conventional commits (`type(scope): summary`), no co-author trailers, no em or en dashes, and no emojis.

## Security and licensing

Report suspected value leaks via [GitHub private vulnerability reporting](SECURITY.md#reporting), not a public issue or PR. Reproduce with synthetic values only; never include live credentials. This project is [GPL-3.0-or-later licensed](LICENSE). Contributions are submitted under GPL-3.0-or-later; no CLA is required. See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.
