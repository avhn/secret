# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged; the plugin manifest version 0.1.0 is not a release tag.

## [Unreleased]

### Added

- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Changed

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Made redaction stop the child on filter failure instead of risking unfiltered output.

### In progress

- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); no Go cutover or release is claimed yet.
