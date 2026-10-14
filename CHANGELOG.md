# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has been tagged; the plugin manifest version 0.1.0 is not a release tag.

## [Unreleased]

### Added

- Bounded Go Codex patch-header checks for add/update/delete/move paths, physical aliases and explicit workdirs, with malformed patch denial and synthetic fuzz coverage; installed hooks remain unchanged.

- Default Go hook Bash AST analysis with 64 KiB envelopes, 40 KiB fragments, explicit wrapper and grep/sed/split option arity, scoped directory checks and value-free denials. The installed Bash hook and plugin manifests remain unchanged.
- Mechanically generated denied-command variants, 76 permanent synthetic audit envelopes, and exact reviewed default-hook divergences with no pending-M2 categories. See the [tightening table](docs/design/hook-tightening.md) for deliberate differences and local evidence.

- Bounded Go PreToolUse envelope and protected-path checks with `secret hook claude|codex`, synthetic decoding and alias tests, fuzz seed, and exact Bash-vs-Go hook case inventories. The active installed hook remains Bash; default Go shell analysis and search certification are now ready for review.
- Alternate `SECRET_CLI` executable support for the CLI and provider shell suites, a tagged disposable Go backend stub, and per-case Go divergence checking in CI on the existing runners. The default Go build ignores stub environment variables.
- Focused Go checks for stub isolation, failure injection, private secret directory permissions and unlabeled stash section reset.

- Unix Go run and exec child environment selection, two-stream literal filtering and supervised child execution with synthetic Bash run goldens. Windows rejects both until its separate child-supervision gate.

- Machine-checked synthetic shell case inventories with a Go format test and isolated provider CI checks.

- A Go module skeleton and Go CI on Linux, macOS and Windows runners.
- Explicit label sections and label-aware selection for file and keystore records.
- Manifest-backed keystore dispatch, Linux libsecret and macOS Keychain backends, with isolated provider tests.
- Codex shell and patch guard support and a Codex plugin bundling the guard and skill.

### Fixed

- Bash guard now denies custom Git aliases without reading Git configuration, analyzes additional shell applets and quoted option names, parses sed scripts before accepting them, and treats indirect environment assignments as uncertain for subsequent consumers.

- Shipped Bash guard closes multi-exec find, attached and multiline sed reads, cdable-variable directory changes, and BusyBox tar stdout extraction. Custom Git aliases are denied; inline transport configuration and indeterminate object sources deny content reads, while inherited editor and pager settings no longer block ordinary Git commands.
- Shipped Bash guard now emits a denial for malformed nonempty requests and analysis errors, gates content-producing Git calls on bounded tracked index names, checks command-running options and inherited editor settings, and tightens find, xargs, archive, directory stack, proc/dev, jq, sed and awk inputs. Ignored untracked files do not block safe Git history forms.
- Ripgrep configuration certification now resolves only its own config path instead of running a platform-dependent directory scan on a single file.
- Shipped Bash guard now denies control bytes, bounded Git history and archive reads, unsafe shell hook variables, interpreter environment and literal script readers, indented Codex patch paths, and audited reader-option, cd, find and glob bypasses.

- Installed Bash guard now denies protected Git grep pager searches, clustered grep/sed file inputs, cd option traversal and brace-expanded Grep selectors.

### Changed

- Go stash now protects the designated secrets directory, correctly resets an unlabeled stash following a labeled section, and matches the Bash stale-lock timeout hint. The tagged stub rejects invalid backend bytes and supports put, get and manifest-publish failure injection.

- Hardened the guard's protected file and input-role detection, command parsing, search-scope checks and credential-printer rules.
- Bounded Go provider output and inherited-pipe waits, with Unix process-group cancellation. Go run now times out blocked output sinks, selects child commands using the constructed PATH, and validates usage before Windows launch rejection. Missing option arguments exit 1 like Bash. Replaced repeated redaction rescans with a streaming matcher.

### In progress

- M2 default-hook parity and hardening are ready for review, not a host cutover. Fixed config reassignment, wrapper clusters, previously unwalked AST expressions, printer-pipe redirects and assignments, combined printer flags, symlinked ancestors before parent traversal, Grep selectors, and tar mode parsing. Local Go, race, fuzz and retained Bash checks pass; real-host and cross-platform gates remain pending.

- Go inventory and human-only CLI commands have synthetic Bash-generated parity cases and CI drift checks; usage exits 1 like Bash, Unix run and exec now have synthetic Bash goldens, and the Bash CLI is still active.
- Go libsecret and Keychain transports now use stdin-only value writes, exact service/account lookups, and disposable provider integration tests in CI; provider validation is pending isolated runners.
- Go store writes now use an anchored parent for private atomic replacement and the shared Bash secrets-directory lock for file and backend transactions, alongside validated v1 manifests, with Bash-generated stash byte goldens and process-concurrency checks. Backend dispatch has a test-only directory stub, readback-before-publish ordering, and unsupported real-provider placeholders; the Bash CLI remains active.
- Go file-store parsing, resolution, label selection, and merge helpers have synthetic tests and Bash-generated golden assertions, including an extended selection corpus and CI drift check; runner validation remains pending.
- The Go rewrite is tracked in [ROADMAP.md](ROADMAP.md); no Go cutover or release is claimed yet.
