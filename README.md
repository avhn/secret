<h1 align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="resources/logo-mark-dark.svg"><img src="resources/logo-mark.svg" width="88" height="88" alt=""></picture><br>Secret</h1>

<p align="center">
  Let coding agents use your credentials without reading them.
</p>

<p align="center">
  <a href="https://github.com/avhn/secret/releases"><img alt="Release" src="https://img.shields.io/github/v/release/avhn/secret"></a>
  <a href="https://github.com/avhn/secret/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/avhn/secret/ci.yml?branch=main&label=ci"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/avhn/secret"></a>
  <a href="docs/setup.md"><img alt="MCP: stdio" src="https://img.shields.io/badge/MCP-stdio-000000?logo=modelcontextprotocol&logoColor=white"></a>
  <a href="docs/install.md"><img alt="Platforms: macOS, Linux, Windows" src="https://img.shields.io/badge/platforms-macOS%20%7C%20Linux%20%7C%20Windows-6A4BFF"></a>
</p>

**Secret lets a coding agent run commands that need your credentials while the
values stay out of the conversation.** The agent works with key names; the
`secret` CLI puts the selected value into the child program's environment and
replaces it with `<redacted>` in that program's output.

```console
$ secret show ~/.secrets.env
API_TOKEN=<40 bytes>
$ secret run -f ~/.secrets.env --key API_TOKEN -- ./deploy.sh
deploying with token <redacted> ... ok    (illustrative deploy output)
```

It is three parts that work together:

| Part | What it does |
| --- | --- |
| `secret` CLI | Stores values (hidden prompt, private atomic writes), shows names with masked lengths, runs a program with selected keys and redacts loaded literal values from its stdout and stderr. |
| Names-only MCP server | `secret mcp --store REF` exposes four read-only tools (`list`, `show`, `diff`, `health`) over stdio for explicitly allowlisted stores. It never returns values, value hashes or lengths. |
| Guard hook and agent skill | A Claude Code and Codex plugin that denies known secret-reading tool calls (store and credential files, environment dumps, credential printers, clipboard reads, `secret get` and `secret exec`) and teaches the agent the safe workflow. |

Accident prevention, not a sandbox: see [Security limits](#security-limits).

## Install

Install or update the Secret CLI to the latest release.

Linux/macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.6.2/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/avhn/secret/v0.6.2/install.ps1 | iex
```

No GitHub account or gh is needed; rerunning updates the installation.
See [pins, paths and verification](docs/install.md).

## Quick start

In your own terminal, stash a value at the hidden prompt. These are illustrative paths:

```sh
secret stash ~/.secrets.env API_TOKEN                       # you: hidden prompt, never argv or chat
secret list                                                 # store paths, never contents
secret show ~/.secrets.env                                  # API_TOKEN=<40 bytes>
secret run -f ~/.secrets.env --key API_TOKEN -- ./deploy.sh # child gets the value, output is redacted
```

Then ask your agent to "deploy with API_TOKEN from ~/.secrets.env". It needs only
the store reference and the key name.

More that `run` and its siblings can do, all in [usage](docs/usage.md):

- **Select precisely**: `--key` (required), `--optional-key`, several `-f` stores
  (later wins). Only selected keys reach the child.
- **Environments and labels**: `[env=dev]` sections in a store, selected with
  `--env dev` or `--label name=value`.
- **Private templates**: `--template-file` renders `{{KEY}}` placeholders into a
  private 0600 file and passes its path in `SECRET_TEMPLATE_FILE`.
- **Clipboard**: `secret clip FILE KEY [SECONDS]` copies a value and clears it
  after 45 seconds unless you copied something else.

## Where values can live

Default stores are plain `KEY=VALUE` files: `~/.secrets.env` and
`~/.secrets/*.secret`. A bare `NAME` means `~/.secrets/NAME.secret`. Other
backends are selected explicitly by reference and work with the same commands.

| Reference | Backend | Linux | macOS | Windows | Notes |
| --- | --- | --- | --- | --- | --- |
| path, `NAME`, `file:PATH` | dotenv-style file, private permissions | yes | yes | yes | Default; the only kind `list` discovers by default. [usage](docs/usage.md) |
| `keychain:NAME` | macOS Keychain | no | yes | no | `SECRET_KEYCHAIN` selects a keychain path. [usage](docs/usage.md) |
| `libsecret:NAME` | Secret Service through `secret-tool` | yes | no | no | Needs an unlocked session. [usage](docs/usage.md) |
| `wincred:NAME` | Windows Credential Manager | no | no | yes | 2560-byte value limit. [windows](docs/windows.md) |
| `pass:NAME` | pass 1.7.4 with your GnuPG setup | yes | yes | no | You initialize the password store. [pass](docs/pass.md) |
| `age:NAME` | age-encrypted file, X25519 keys | yes | yes | no | Explicit `--age-identity`; create with `age-init`. [age](docs/age.md) |

Keystore backends keep a names-only manifest under `~/.secrets`, so `list` and
`show` read names without fetching a value.

**1Password and Bitwarden.** Copy items into a store with a human-run,
insert-only import through the vendor CLI (`op` or `bw`) that you have already
signed in. Explicit field mappings are required:

```sh
secret import --from op:ITEM_ID --into file:/absolute/team.secret --map password=API_TOKEN
secret import --from bw:ITEM_ID --into file:/absolute/team.secret --map login.password=API_TOKEN
secret import --from dotenv:/absolute/old.env --into file:/absolute/team.secret
```

Reading `op://` references live, without importing, is planned: the
`onepassword:` backend exists in the source but is switched off with no runtime
override until a licensing review and isolated provider testing pass; see
[its status](docs/onepassword.md). `secret export` copies records from one store
to a keystore or age store (for example file to Keychain); plaintext export
targets are refused.

## For agents

If you are a coding agent reading this, the rules are short. The full version is
the [agent skill](skills/secrets/SKILL.md); setup is in [docs/setup.md](docs/setup.md).

| You may run | Purpose |
| --- | --- |
| `secret list` | Default store paths, without opening them. |
| `secret show FILE` | Key names, masked lengths and labels. |
| `secret run -f FILE --key KEY -- CMD` | Run a command with the value in its environment and redacted output. |
| `secret clip FILE KEY` | Only when the user explicitly asks for the clipboard. |
| MCP tools `list`, `show`, `diff`, `health` | Names-only metadata for stores the human allowlisted. |

| Human only: never run it | Why |
| --- | --- |
| `secret get` | Prints a value to a terminal. |
| `secret exec` | Unfiltered `run`, for human-configured launchers. |
| `secret stash` | The human types the value at a hidden prompt. |
| `import`, `export`, `rotate`, `rename`, `delete`, `age-init`, `age-rekey` | Operator commands; require real terminals and hidden confirmation. |

- Use the exact store reference the human gave you. Do not search for, open,
  `cat`, `grep` or patch store files, and do not print or transform values
  (no `echo $KEY`, `env`, base64).
- Prefer stdin or header files over arguments, so a value does not appear in
  the child's argv:
  `secret run -f FILE --key API_TOKEN -- bash -c 'printf "Authorization: Bearer %s\n" "$API_TOKEN" | curl -fsS -H @- URL'`
- Missing key: ask the human to run `secret stash FILE KEY` in their own
  terminal. Never ask for a value in chat.
- Denied by the guard: narrow the request or follow its hint. Do not disguise the
  command, disable the hook or change permissions. The installed hooks also deny
  newer subcommands such as `diff`, `doctor`, `audit` and `mcp` from the shell.

## Connect your agent

**Names-only MCP server.** Register it with the installed executable's concrete
absolute path and an exact human-approved store reference. Do not discover or
read stores:

```sh
claude mcp add --transport stdio --scope user secret -- "/ABSOLUTE/INSTALL DIR/secret" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

Reconnect the client and verify list/show/diff/health. The server is off without
`--store`, has no network listener and cannot be widened by a request.
[Setup](docs/setup.md#clients) covers Claude Code, Claude Desktop (MCPB bundle
or JSON), Codex, ChatGPT desktop, OpenCode, Cursor and VS Code, Windows
equivalents, and the MCP Registry name `io.github.avhn/secret` (see the
[release status](CHANGELOG.md) for the currently published record).

**Guard hook and skill.** Optional plugin for Claude Code:

```text
/plugin marketplace add avhn/secret
/plugin install secret@secret
```

and for Codex:

```sh
codex plugin marketplace add avhn/secret
codex plugin add secret@secret
```

The plugin installs the Bash guard and the [agent skill](skills/secrets/SKILL.md),
not an MCP registration. Codex requires explicit hook trust in `/hooks`,
including re-trust after changes. Also install the protective ripgrep config;
see [plugin and manual-hook instructions](docs/install.md#checkout-installation-and-bash-compatibility).
Go hooks remain inactive; installation and synthetic tests do not prove host
fail-closed protection.

**Launching other MCP servers with a credential.** For a launcher you configure
yourself, `exec` supplies selected values without filtering the server's stdio.
It works on macOS, Linux and Windows. `-f` takes a plain store path, not `file:`:

```sh
"/ABSOLUTE/INSTALL DIR/secret" exec -f "/ABSOLUTE/STORE DIR/.secrets.env" --key OPENPROJECT_API_TOKEN -- uvx openproject-ce-mcp@0.4.1
```

This is not the names-only server or an agent retrieval route. Output is
unfiltered and can disclose values. Review the server first; see
[client JSON, Windows paths and shutdown limits](docs/setup.md#configured-value-consuming-launchers).

## Command overview

| Command | Who | What |
| --- | --- | --- |
| `list`, `show` | agent or human | Store paths; key names with masked lengths (`<stored>` for keystores). `--format=json` is names-only. |
| `run` | agent or human | Child with selected keys, redacted stdout and stderr, optional `--template-file`. |
| `clip` | on human request | Clipboard copy with timed conditional clear. |
| `stash` | human | Hidden prompt or stdin; private atomic write. |
| `get`, `exec` | human | Print one value to a terminal; unfiltered child. |
| `import`, `export` | human operator | Insert-only transfer from dotenv, `op`, `bw`, or between stores; `--dry-run`. |
| `rotate`, `rename`, `delete` | human operator | Lifecycle of one exact record. |
| `age-init`, `age-rekey` | human operator | Create or rekey an encrypted store. |
| `diff`, `doctor`, `audit`, `completion` | human | Names-only comparison, diagnostics, opt-in audit log queries, completion candidates. |
| `mcp` | client launcher | Names-only stdio server. |

`secret help` prints the full reference. The site lists the same
[tools and commands](https://avhn.github.io/secret/tools/).

## Security limits

- The CLI supplies selected values to a child and redacts **literal** output.
  Redaction does not catch base64, URL encoding, substrings or other transformations.
- The guard is heuristic. It denies known secret-reading operations but cannot
  contain a determined agent, arbitrary child behavior or tools it never sees,
  including MCP search tools.
- Metadata can reveal key names, labels, paths and provider account IDs.
- Default file stores are plaintext at rest with private permissions; choose a
  keystore or `age:` store for encryption at rest.
- No fail-closed host protection is claimed.

Treat this as one layer, not the boundary. Read the
[full threat model](SECURITY.md#what-it-does-not-protect).

## More

- [Usage: stores, providers, labels, operator commands, templates](docs/usage.md)
- [Verify, update or roll back](docs/install.md), with explicit Bash rollback at `compat/secret`
- [Windows support and limits](docs/windows.md)
- [Security model and reporting](SECURITY.md)
- [CONTRIBUTING.md](CONTRIBUTING.md) for synthetic tests and PR guidance,
  [AGENTS.md](AGENTS.md) for agent rules, [ROADMAP.md](ROADMAP.md) for milestones

## License

[GPL-3.0-or-later](LICENSE), copyright Mert Dede.
