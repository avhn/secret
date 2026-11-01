<h1 align="center"><picture><source media="(prefers-color-scheme: dark)" srcset="resources/logo-mark-dark.svg"><img src="resources/logo-mark.svg" width="88" height="88" alt=""></picture><br>secret</h1>

<p align="center">
  Let coding agents use your credentials without reading them.
</p>

<p align="center">
  <a href="https://github.com/avhn/secret/releases"><img alt="Release" src="https://img.shields.io/github/v/release/avhn/secret"></a>
  <a href="https://github.com/avhn/secret/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/avhn/secret/ci.yml?branch=main&label=ci"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/avhn/secret"></a>
  <a href="docs/setup.md"><img alt="MCP: stdio" src="https://img.shields.io/badge/MCP-stdio-000000?logo=modelcontextprotocol&logoColor=white"></a>
  <a href="docs/install.md"><img alt="Go CLI platforms: macOS, Linux, Windows" src="https://img.shields.io/badge/Go_CLI-macOS%20%7C%20Linux%20%7C%20Windows-6A4BFF"></a>
  <a href="docs/install.md"><img alt="Go CLI architectures: amd64 and arm64" src="https://img.shields.io/badge/Go_CLI_arch-amd64%20%7C%20arm64-6A4BFF"></a>
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

Needs an authenticated GitHub CLI (`gh auth login`), plus curl and Python 3 on
Linux/macOS or curl.exe on Windows. Run from your own terminal:

Linux/macOS:

```sh
sh -c 'umask 077; d=$(mktemp -d) || exit
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.4.1/install.sh -o "$d/install.sh" && sh "$d/install.sh" "$@"
status=$?; rm -rf "$d"; exit "$status"' sh
```

Windows PowerShell:

```powershell
& { $ErrorActionPreference = 'Stop'; $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $d | Out-Null
try { irm https://raw.githubusercontent.com/avhn/secret/v0.4.1/install.ps1 -OutFile "$d\install.ps1" -ErrorAction Stop; & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File "$d\install.ps1" @args; $status = $LASTEXITCODE }
finally { Remove-Item -LiteralPath $d -Recurse -Force }; exit $status }
```

The installer verifies the release attestation (not just a checksum) and puts
`secret` at `~/.local/bin/secret` or `$HOME\.local\bin\secret.exe`. It does not
register MCP, read stores or activate hooks. Unix does not edit PATH; Windows adds
only its install directory to user PATH. Use the printed absolute path.

<details>
<summary>Authentication, flags and bootstrap trust</summary>

v0.4.1 is the GitHub Latest release. Install dependencies through trusted channels.
Run `gh auth login` privately, or supply `GH_TOKEN` through your trusted credential
environment without displaying it. Never paste tokens into chat or client configuration.
If you see `secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry`,
authenticate gh privately or correct its trusted environment, then retry without printing a token.

Both snippets download first, run only after a successful download and preserve
failure through cleanup. Append flags after the final `sh` or PowerShell brace.
The PowerShell bypass applies only to that one child process, not persistent
policy; centrally enforced Group Policy can still take precedence. Raw executables
do not rehash themselves on every run. See
[bootstrap trust and verification](docs/install.md#standalone-install-and-bootstrap-trust)
before running a downloaded installer.

</details>

### Or give your agent this prompt

```text
Follow https://github.com/avhn/secret/blob/v0.4.1/docs/setup.md to install and register secret MCP; ask me for the exact intended store references, never discover or read stores, handle values, run operator consent commands, or bypass a guard.
```

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
  MCP Registry name `io.github.avhn/secret`. Registry publication of v0.4.1 is
  pending the macOS public-install jobs; the active record remains 0.3.4.
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
