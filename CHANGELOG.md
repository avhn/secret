# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged; the plugin manifest version 0.1.0 is not a release tag.

## [Unreleased]

### Added

- Unix Go run and exec child environment selection, two-stream literal filtering and supervised child execution with synthetic Bash run goldens. Windows rejects both until its separate child-supervision gate.

- Machine-checked synthetic shell case inventories with a Go format test and isolated provider CI checks.

- A Go module skeleton and Go CI on Linux, macOS and Windows runners.
- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Changed

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Made redaction stop the child on filter failure instead of risking unfiltered output.

### In progress

- Go inventory and human-only CLI commands have synthetic Bash-generated parity cases and CI drift checks; usage exits 1 like Bash, Unix run and exec now have synthetic Bash goldens, and the Bash CLI is still active.
- Go libsecret and Keychain transports now use stdin-only value writes, exact service/account lookups, and disposable provider integration tests in CI; provider validation is pending isolated runners.
- Go store writes now use an anchored parent for private atomic replacement and the shared Bash secrets-directory lock for file and backend transactions, alongside validated v1 manifests, with Bash-generated stash byte goldens and process-concurrency checks. Backend dispatch has a test-only directory stub, readback-before-publish ordering, and unsupported real-provider placeholders; the Bash CLI remains active.
- Go file-store parsing, resolution, label selection, and merge helpers have synthetic tests and Bash-generated golden assertions, including an extended selection corpus and CI drift check; runner validation remains pending.
- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); no Go cutover or release is claimed yet.
