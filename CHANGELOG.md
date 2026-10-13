# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged; the plugin manifest version 0.1.0 is not a release tag.

## [Unreleased]

### Added

- Alternate `SECRET_CLI` executable support for the CLI and provider shell suites, a tagged disposable Go backend stub, and per-case Go divergence checking in CI on the existing runners. The default Go build ignores stub environment variables.
- Focused Go checks for stub isolation, failure injection, private secret directory permissions and unlabeled stash section reset.

- Unix Go run and exec child environment selection, two-stream literal filtering and supervised child execution with synthetic Bash run goldens. Windows rejects both until its separate child-supervision gate.

- Machine-checked synthetic shell case inventories with a Go format test and isolated provider CI checks.

- A Go module skeleton and Go CI on Linux, macOS and Windows runners.
- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Changed

- Go stash now protects the designated secrets directory, correctly resets an unlabeled stash following a labeled section, and matches the Bash stale-lock timeout hint. The tagged stub rejects invalid backend bytes and supports put, get and manifest-publish failure injection.

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Bounded Go provider output and inherited-pipe waits, with Unix process-group cancellation. Go run now times out blocked output sinks, selects child commands using the constructed PATH, and validates usage before Windows launch rejection. Missing option arguments exit 1 like Bash. Replaced repeated redaction rescans with a streaming matcher.

### In progress

- Go inventory and human-only CLI commands have synthetic Bash-generated parity cases and CI drift checks; usage exits 1 like Bash, Unix run and exec now have synthetic Bash goldens, and the Bash CLI is still active.
- Go libsecret and Keychain transports now use stdin-only value writes, exact service/account lookups, and disposable provider integration tests in CI; provider validation is pending isolated runners.
- Go store writes now use an anchored parent for private atomic replacement and the shared Bash secrets-directory lock for file and backend transactions, alongside validated v1 manifests, with Bash-generated stash byte goldens and process-concurrency checks. Backend dispatch has a test-only directory stub, readback-before-publish ordering, and unsupported real-provider placeholders; the Bash CLI remains active.
- Go file-store parsing, resolution, label selection, and merge helpers have synthetic tests and Bash-generated golden assertions, including an extended selection corpus and CI drift check; runner validation remains pending.
- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); no Go cutover or release is claimed yet.
