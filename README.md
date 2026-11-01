<h1 align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="resources/logo-mark-dark.svg"><img src="resources/logo-mark.svg" width="88" height="88" alt=""></picture><br>secret</h1>

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

**A local credential CLI, a names-only MCP server, and a guard hook for coding agents.**

Agents see key names, labels and paths, never values through the names-only interface.
The CLI passes selected values directly to programs; the guard denies known store-reading operations.

## How it works

1. The agent asks for a credential by key name, not its value.
2. `secret` hands the selected value directly to the program's environment.
3. `secret run` redacts loaded literal values from stdout and stderr.

Accident prevention, not a sandbox.

## Install

Install or update the secret CLI to the latest release.

Linux/macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.5.0/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/avhn/secret/v0.5.0/install.ps1 | iex
```

No GitHub account or gh is needed; rerunning updates the installation.

See [pins, paths and verification](docs/install.md).

## Use it

In your own terminal, stash a value with a hidden prompt. Agents can use `show`
and `run`, but must never enter or retrieve values. These are illustrative paths:

```sh
secret stash ~/.secrets.env API_TOKEN
secret show ~/.secrets.env
secret run -f ~/.secrets.env --key API_TOKEN -- ./deploy.sh
```

Register names-only MCP using the installed executable's concrete absolute path
and an exact human-approved store reference. Do not discover or read stores:

```sh
claude mcp add --transport stdio --scope user secret -- "/ABSOLUTE/INSTALL DIR/secret" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

Reconnect the client and verify list/show/diff/health. See
[Windows equivalents and client setup](docs/setup.md#claude-code).

## Use it to launch other MCP servers

For a human-configured client launcher, `exec` supplies selected values without
filtering the server's stdio. It works on macOS, Linux and Windows; Windows
long-lived exec shipped in v0.3.4. `-f` takes a plain store path, not `file:`:

```sh
"/ABSOLUTE/INSTALL DIR/secret" exec -f "/ABSOLUTE/STORE DIR/.secrets.env" --key OPENPROJECT_API_TOKEN -- uvx openproject-ce-mcp@0.4.1
```

This is not the names-only server or an agent retrieval route. Output is
unfiltered and can disclose values. Review the server and configure this yourself;
see [client JSON, Windows paths and shutdown limits](docs/setup.md#configured-value-consuming-launchers).

## Next steps

- [Set up clients](docs/setup.md#clients), including the Claude Desktop MCPB and
  MCP Registry name `io.github.avhn/secret`. v0.5.0 is prepared, not yet published to the Registry.
- [Verify, update or roll back](docs/install.md), with explicit Bash rollback at `compat/secret`.
- [Windows support and limits](docs/windows.md).
- [Security model and reporting](SECURITY.md).

## Guard hook

The optional [Claude Code and Codex plugins](docs/install.md#checkout-installation-and-bash-compatibility)
install the Bash guard and [agent skill](skills/secrets/SKILL.md), not an MCP registration.
Codex requires explicit hook trust in `/hooks`, including re-trust after changes.
Install the protective ripgrep config and review the manual-hook instructions there.
Go hooks remain inactive; installation and synthetic tests do not prove host fail-closed protection.

## More workflows

See [detailed usage, providers, labels, operator commands and templates](docs/usage.md),
[encrypted age stores](docs/age.md), [inactive 1Password scaffolding](docs/onepassword.md)
and [pass stores](docs/pass.md).

## Security limits

Literal redaction does not catch base64, URL encoding, substrings or other
transformations. The guard cannot contain a determined agent, arbitrary child
behavior or tools it never sees, including MCP search tools. Metadata can reveal
names, labels, paths and provider account IDs. Treat this as one layer, not the
boundary. Read the [full threat model](SECURITY.md#what-it-does-not-protect).

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for synthetic tests and PR guidance,
[AGENTS.md](AGENTS.md) for agent rules and [ROADMAP.md](ROADMAP.md) for milestones.

## License

[GPL-3.0-or-later](LICENSE), copyright Mert Dede.
