# secret

Let coding agents use your credentials without reading them.

An agent with a shell can `cat .env`, run `printenv`, or grep a token out of a
config file, and the value lands in its context, its logs, and possibly a
provider's servers. `secret` gives the agent a sanctioned path instead: it sees
key names and masked lengths, picks the keys a command needs, and the values go
straight into that child process's environment.

Three parts, usable together or alone:

| Part                      | What it does                                                                                                                                                                                                |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bin/secret`              | Verified Go CLI launcher (no Bash fallback). Parses `KEY=VALUE` stores (never sources them), shows masked names, runs a child with selected keys, and redacts every loaded value from the child's stdout and stderr.                                |
| `hooks/guard-secrets`     | Claude Code and Codex `PreToolUse` hook. Denies reads of store files, environment dumps, credential printers (`gh auth token`, `security -w`, `pbpaste`, ...) and searches that would print store contents. |
| `skills/secrets/SKILL.md` | Tells the agent how to work with the CLI and how to recover from a guard denial without asking for values in chat.                                                                                          |

## What this is not

**Accident prevention, not a sandbox.** It stops an agent from reading a secret
by habit or by mistake. It does not stop a determined or compromised agent with
a shell: transformed output (base64, URL encoding, substrings) is not redacted,
shell indirection the guard cannot parse is allowed unless it names a protected
file or operation, MCP search tools are not covered, and the guard makes no
decision when its input is malformed (without `jq` it denies every request).
Treat it as one layer, not the boundary.

## Install

### Opt-in Go CLI and names-only MCP

[Canonical setup](docs/setup.md) covers installation, approved store references,
per-client registration, verification, updates and removal. The v0.3.4 release
is being prepared; these pinned commands require its published assets and never
select latest or fall back to another version.

Prerequisites: authenticated GitHub CLI gh, plus curl and Python 3 on Unix or
curl.exe on Windows. Install tools through trusted channels. Run `gh auth login`
yourself in a private terminal, or supply `GH_TOKEN` through your trusted
credential environment without displaying it. Never paste a token into chat
or client configuration.

```sh
sh -c 'umask 077; d=$(mktemp -d) || exit
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.3.4/install.sh -o "$d/install.sh" && sh "$d/install.sh" "$@"
status=$?; rm -rf "$d"; exit "$status"' sh
```

Windows PowerShell:

```powershell
& { $ErrorActionPreference = 'Stop'; $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $d | Out-Null
try { irm https://raw.githubusercontent.com/avhn/secret/v0.3.4/install.ps1 -OutFile "$d\install.ps1" -ErrorAction Stop; & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File "$d\install.ps1" @args; $status = $LASTEXITCODE }
finally { Remove-Item -LiteralPath $d -Recurse -Force }; exit $status }
```

These download-first snippets run only after the download succeeds and preserve
failure through cleanup. Append installer flags after the final `sh` or closing
PowerShell brace; see [setup](docs/setup.md#install) for details. PowerShell runs
the file in a child of the same host with `-NoProfile -ExecutionPolicy Bypass`
and propagates its exit code after cleanup. The bypass applies only to that one
child process, not any persistent policy; centrally enforced Group Policy can
still take precedence.

If an installer reports
`secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry`,
authenticate gh privately or correct its trusted environment, then retry without
pasting or printing a token.

The bootstrap trusts GitHub HTTPS, repository/tag governance and the reviewed
installer before verification. Both require gh and verify release attestations,
not checksums alone; `SECRET_RELEASE_COMMIT` optionally pins an independently
authenticated full C. Unix also needs curl and Python 3; Windows needs curl.exe.
Download/review/run or a trusted checkout offers stronger bootstrap review.
Final CLI names and destinations described below ship from **v0.3.5 onward**.
The download snippets install their pinned release, not main. The published
v0.3.4 installer uses `secret-go` on Unix and
`%LOCALAPPDATA%\Programs\secret\secret-go.exe` on Windows, not the final paths.
Use the printed executable path for that release; do not infer the installed
name from the checkout documentation. Update release pins together in the coordinated identity bump; never replace
published assets or tags.

From v0.3.5 onward, installers publish `secret` / `secret.exe` and print the absolute path.
Defaults are `~/.local/bin/secret` on Unix and `$HOME\.local\bin\secret.exe`
on Windows (native profile fallback when HOME is absent). A verified install
atomically replaces a safe existing CLI; `compat/secret` is explicit Bash rollback.
Unix does not edit PATH; Windows adds only its directory to user PATH. Neither
registers MCP, reads stores or activates hooks. Raw executables do not have the
checkout launcher's per-execution rehash.

Paste to your agent: Follow https://github.com/avhn/secret/blob/v0.3.4/docs/setup.md to install and register secret MCP; ask me for exact store references, never discover/read stores, handle values or bypass a guard.

| Surface | Support and evidence |
| --- | --- |
| Go CLI | v0.3.4 targets Linux, macOS and Windows amd64/arm64; new native candidate/public-install gates remain required. v0.2.3 Linux/macOS publication is complete. |
| Local stdio MCP | Opt-in `mcp --store STORE_REFERENCE`; list/show/diff/health only, never values. Metadata can still reveal names, labels, paths and account IDs. |
| Desktop bundle | `secret-v0.3.4-desktop.mcpb`: macOS universal and Windows amd64; locked-CLI/native smoke validation is not host-tested Desktop installation. |
| Registry | Name `io.github.avhn/secret`; publication is separately owner-gated, not claimed here. |
| Plugins and hooks | All four manifests are 0.3.4; installed hooks remain the Bash guard. M4.1 Go activation is waiting sponsorship, with no fail-closed host claim. |

See [installation and rollback](docs/install.md) for pins, dependencies, offline
options and failure recovery, and [release approvals](docs/release.md).

### Verified CLI, Bash guard and skill

Requirements: bash 3.2 or newer (stock macOS bash works), perl, and jq for the
guard and explicit `compat/secret` rollback. The final CLI is Go; CLI naming
does not activate Go hooks or change MCP registration.

The checkout `bin/secret` launcher requires a release checksum commit C with
its committed checksum manifest. It works at an authenticated release tag that
includes this change, **v0.3.5 onward**, after verified cache installation. A
plain main checkout has no current release checksum manifest and exits 70;
it does not build from source or fall back to Bash.

For main/clone users, use the standalone installer above (and its printed path),
or explicitly select the retained Bash implementation:

```bash
git clone https://github.com/avhn/secret ~/.local/share/secret
bash ~/.local/share/secret/compat/secret help
```

For a released checkout launcher, first select the authenticated release C as
shown in [installation](docs/install.md), then preinstall its verified cache and
link that release checkout's `bin/secret`. Do not link main's launcher expecting
it to work without release metadata.

The guard and skill, as a Claude Code plugin:

```text
/plugin marketplace add avhn/secret
/plugin install secret@secret
```

For Codex CLI, install the plugin from this repository's Codex marketplace.
It bundles the guard and skill, without modifying `~/.codex/hooks.json`:

```bash
codex plugin marketplace add avhn/secret
codex plugin add secret@secret
```

In Codex, open `/hooks` and trust the installed secret hook before relying on
it. Untrusted hooks are listed but do not run; review and re-trust the hook
when it changes. `/plugins` lets you inspect the installed plugin. The plugin
does not put `bin/secret` on `PATH`. Install the CLI separately if you want to
use it. Main/clone users should choose the standalone installer or invoke
`bash ~/.local/share/secret/compat/secret` explicitly. A `bin/secret` symlink
requires an authenticated v0.3.5-or-later release checkout at C, not main, plus
its verified cache and `~/.local/bin` on `PATH`.

If your Codex version has no plugin marketplace support, use the manual route
with a checkout of the repo. Copy the hook template with an absolute command
path and install the skill in the user skills root:

```bash
mkdir -p ~/.codex ~/.codex/skills
jq --arg command "$HOME/.local/share/secret/hooks/guard-secrets" \
  '.hooks.PreToolUse[].hooks[].command = $command' \
  ~/.local/share/secret/codex/hooks.json >~/.codex/hooks.json
ln -s ~/.local/share/secret/skills/secrets ~/.codex/skills/secrets
```

If `~/.codex/hooks.json` already exists, merge its `PreToolUse` groups rather
than replacing the file. Codex also accepts inline `[hooks]` in `config.toml`;
the snippet uses `hooks.json` so it can be copied without changing that file.
Open `/hooks` to trust the manual hook as well. Codex sends shell commands
under the `Bash` hook name and patches under `apply_patch`. The guard needs
`jq` and `perl` on the hook's `PATH`.

The guard allows plain `rg` because ripgrep can be told to skip store files.
Install the protective config, or merge its globs into your own:

```bash
mkdir -p ~/.config/ripgrep
cp ~/.local/share/secret/examples/ripgreprc ~/.config/ripgrep/config
export RIPGREP_CONFIG_PATH="$HOME/.config/ripgrep/config"  # in your shell profile
```

## Opt-in age stores in the staged Go CLI

M5d adds explicit `age:NAME` encrypted file stores on Linux/macOS, with reviewed
`filippo.io/age v1.3.2`, whole-store authenticated reads and ciphertext-only
atomic writes. `age-init` is create-only and `age-rekey` verifies the new identity
before publication; both require real terminals and exact target confirmation.
Key files must be private under `HOME/.secrets/.age-keys/`, and value-consuming
commands require explicit `--age-identity FILE`. Names-only interfaces need no
identity, but their outer metadata is unauthenticated. Use `list --backend age`;
default discovery and the Bash CLI are unchanged. Windows age filesystem
operations remain unsupported even though M5a's separate Windows CLI gate passed.
See [age setup, migration, recovery and limits](docs/age.md). M5d passed its hosted
gate in PR #28; this does not activate hooks or authorize publication.

## Usage

Stores use `KEY=VALUE` lines: `~/.secrets.env` and `~/.secrets/*.secret`
by default (`SECRETS_ENV` and `SECRETS_DIR` override them). Exact section
headers such as `[env=dev,region=eu]` scope following assignments; `[]` resets
to unlabeled. Other bracket lines are ignored. Labels use identifier names and
values made of letters, digits, underscores, dots, or hyphens (starting with a
letter, digit, or underscore). A labeled file is no longer plain dotenv for
other tools. Older `secret` versions read all sections as one flat store, so
upgrade before introducing headers.

```bash
secret list                                   # store paths, never contents
secret show ~/.secrets.env                    # API_TOKEN=<40 bytes>
secret stash ~/.secrets.env API_TOKEN         # hidden prompt, atomic write
secret run -f ~/.secrets.env --key API_TOKEN -- ./deploy.sh
secret show --env dev ~/.secrets.env          # selected masked keys and unset keys
secret stash --env dev ~/.secrets.env API_TOKEN
secret run -f ~/.secrets.env --env dev --key API_TOKEN -- ./deploy.sh
```

Explicit `keychain:NAME` and `libsecret:NAME` references use keystore stores;
`file:PATH` forces a literal file path, including paths that look like backend
references. Bare names and paths still use file stores. Keystore names must
contain only letters, digits, underscores, dots, and hyphens (and start with
an alphanumeric or underscore). Each keystore store has a private, atomically
written `~/.secrets/NAME.keys` manifest containing only key names, canonical
labels, and random account identifiers, never values. `list` and `show` use
only the manifest; `show` displays `<stored>` instead of a byte count. `run`
and `exec` load every registered item before selecting keys, so failed lookups
stop the child and `run` can redact values from unselected environments.
`get` and `clip` fetch only the selected item. A failed manifest publish after
a successful backend put can leave an unregistered keystore item.

On Linux, `libsecret:NAME` uses `secret-tool` and an unlocked Secret Service
session. Values are sent to the provider through stdin and retrieved into a
private file. Stash accepts values without a terminal newline or with one
terminal newline (which it removes). Empty values, embedded newlines or CR,
NUL, leading or trailing whitespace, and wrapping quotes are rejected.
On macOS, `keychain:NAME` uses the user's default Keychain, or an explicit
`SECRET_KEYCHAIN` absolute keychain path (only letters, digits, `_`, `.`, `/`,
and `-`; paths requiring quoting are rejected). Values are hex-encoded into a
`security -i` stdin command, never placed in process arguments. Keychain stash
accepts printable UTF-8 text without Unicode controls or line separators;
values outside this subset are rejected because `security -w` is a text interface. A private-file readback
must match before the manifest is published. Reads strip exactly the one newline
added by `security -w`. The test stub remains available for isolated tests;
never use it with real credentials.

`--env dev` means `--label env=dev`; repeat `--label name=value` to select
multiple labels. Without selectors only unlabeled records qualify. For each key,
the most specific matching label set wins; equally specific distinct matches
fail as ambiguous. `show` without selectors lists every record with canonical
sorted labels and masked lengths. `stash` updates only the exact label set,
while `get` and `clip` select the same record as `run`.

`run` exports only the selected keys (`--key` required, `--optional-key`
optional; no selector exports all), and replaces every loaded value in the
child's output with `<redacted>`. Prefer passing values on stdin, since a child
that puts a value in its own argv exposes it to the process list:

```bash
secret run -f ~/.secrets.env --key API_TOKEN -- bash -c \
  'printf "Authorization: Bearer %s\n" "$API_TOKEN" | curl -fsS -H @- https://api.example.test'
```

Human-only commands, which the guard denies to agents:

- `secret get FILE KEY` prints a value, and only to a terminal.
- `secret exec ...` is `run` without redaction, for interactive tools and MCP
  server launchers that need byte-exact stdio.

`secret clip FILE KEY [SECONDS]` copies a value and clears the clipboard after
45 seconds unless you have copied something else since. The value never reaches
the agent's output, so the guard allows it; the skill tells the agent to use it
only when you ask for the clipboard, and reading the clipboard back is denied.

Run `secret help` for the full reference, including exit statuses.

## Staged Go operator workflow (M3)

M3 passed its hosted CI gate (PR #8). These commands are implemented in the Go
CLI through the final `bin/secret` launcher. The CLI-only cutover leaves both
installed guards on Bash. Build
`go build -o /absolute/private/build/secret ./cmd/secret` to try the staged CLI.
The examples below use `secret` for that binary and placeholder store paths.
Invoke operators directly in your own terminal, never through agent tools.

```bash
secret import --from dotenv:/absolute/source.env --into file:/absolute/team.secret
secret import --from op:OPAQUE_ID --into file:/absolute/team.secret --map password=API_TOKEN
secret export --from file:/absolute/team.secret --to libsecret:team --on-conflict=fail
secret rotate file:/absolute/team.secret API_TOKEN --env prod
secret rename file:/absolute/team.secret API_TOKEN SERVICE_TOKEN --env prod
secret delete file:/absolute/team.secret SERVICE_TOKEN --env prod
secret show --format=json file:/absolute/team.secret
secret diff --format=json --env dev --env prod file:/absolute/team.secret
secret doctor --format=json libsecret:team
```

Operators require both stdin and stdout terminals before store access, then exact
hidden confirmation of every target/key/label identity on the controlling terminal.
There is no `--yes`, piped confirmation or operator JSON. Rotation reads the new
value hidden, never in argv. Lifecycle labels identify the exact record. References
must be explicit `file:ABS_PATH`, `keychain:NAME` or `libsecret:NAME`. Import/export
are insert-only; op/bw imports require explicit field mappings. Export requires
`--on-conflict=fail`, a different implemented keystore destination and explicit
selectors for labeled records; without selectors only unlabeled records qualify.
`--dry-run` lists names/conflicts only and still requires real terminals. Doctor
reports tracked recovery candidates and manual verification guidance, not a proven
or complete historical orphan inventory or installed-host trust.

Private templates use literal `{{KEY}}` placeholders and selected keys only:

```bash
secret run -f file:/absolute/team.secret --key API_TOKEN \
  --template-file /absolute/client.template -- ./consumer
```

The child receives the rendered path in `SECRET_TEMPLATE_FILE`, never file contents
in argv. Output still redacts every loaded literal value. Files live under the fixed
`HOME/.secrets/.rendered/<random>/payload`, independent of `SECRETS_DIR`, with 0700
directories and a 0600 payload. Missing/unselected placeholders, unsafe aliases,
`exec` and output-directory options are rejected. The supervisor stops its process
group before normal/error/catchable-signal cleanup. SIGKILL, crashes or power loss
can leave protected plaintext; cleanup is best effort, not secure erasure.

`list/show --format=json`, diff, doctor, completion and audit queries expose only
metadata, never values, hashes or lengths. Metadata may reveal key names, labels,
backend kind, store paths and provider account IDs. Legacy text `show` retains its
masked byte lengths and ordering. Completion emits literal candidates, not shell
code, and reads only explicit `-f` scopes. Audit is off unless an operator receives
`--audit-dir ABS_PATH`; query with `audit --directory ABS_PATH --format=json`.
Names-only events rotate across four private 0600 files capped at 1 MiB each.

MCP is off until explicitly allowlisted, for example
`secret mcp --store file:/absolute/team.secret --store libsecret:team`.
The stdio server exposes only list/show/diff/health, never values or mutation;
requests cannot expand that exact allowlist. Configuring it permits the path and
account metadata above to reach its clients. No network listener or ambient store
discovery is enabled. The unchanged installed hooks conservatively deny new
subcommands, including names-only ones; this feature does not grant an agent a
hook exception. M5a's native Windows CLI, console, storage, Job and Credential
Manager gate passed; [Windows support](docs/windows.md) states its limits and the
separate pending release-asset evidence. No installed-host protection is claimed.
See [CONTRIBUTING.md](CONTRIBUTING.md) for gates and [the M3 plan](docs/design/m3-plan.md)
for the implementation contract.

## Tests

```bash
bash tests/test-secret.sh   # CLI matrix, needs perl, python3 and rg
bash tests/test-backends.sh # disposable keystore stub matrix
bash tests/test-guard.sh    # guard matrix, needs jq
```

The suites use disposable directories and synthetic values only. CI runs them on
Linux and macOS, including stock `/bin/bash` 3.2.

## Development

The Go rewrite is in progress; track milestones in [ROADMAP.md](ROADMAP.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidance and
[AGENTS.md](AGENTS.md) for coding agent rules.

## License

[GPL-3.0-or-later](LICENSE), copyright Mert Dede.

### 1Password scaffolding (inactive)

The staged Go implementation includes test-only read-only 1Password scaffolding.
Default registration, discovery and reads are disabled pending isolated provider
evidence and licensing review. There is no environment switch to enable it.
The Bash CLI, installed hooks and plugin manifests are unchanged. See
[the contract and limitations](docs/onepassword.md); do not point the Bash CLI at
a Go v2 manifest.
