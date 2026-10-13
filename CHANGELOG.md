# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged; the plugin manifest version 0.1.0 is not a release tag.

## [Unreleased]

### Added

- Machine-checked synthetic shell case inventories with a Go format test and isolated provider CI checks.

- A Go module skeleton and Go CI on Linux, macOS and Windows runners.
- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Changed

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Made redaction stop the child on filter failure instead of risking unfiltered output.

### In progress

- Go store writes now use private locked atomic replacement and validated v1 manifests, with Bash-generated stash byte goldens and process-concurrency checks. Backend dispatch has a test-only directory stub, readback-before-publish ordering, and unsupported real-provider placeholders; the Bash CLI remains active.
- Go file-store parsing, resolution, label selection, and merge helpers have synthetic tests and Bash-generated golden assertions, including an extended selection corpus and CI drift check; runner validation remains pending.
- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); no Go cutover or release is claimed yet.
