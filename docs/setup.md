# Set up secret MCP

This is the canonical setup guide for the opt-in secret 0.3.3 local stdio MCP
server. Install, choose exact references, register, reconnect and verify in that
order. The v0.3.3 release is being prepared; the commands below require its
owner-approved published assets. They do not select a different release if those
assets are absent. See [installation](install.md) for checkout/offline options
and [release approvals](release.md) for publication status and trust boundaries.

## Paste to your agent

Follow https://github.com/avhn/secret/blob/v0.3.3/docs/setup.md to install and register secret MCP; ask me for the exact intended store references, never discover or read stores, handle values, run operator consent commands, or bypass a guard.

## For an AI agent

1. Resolve the installed executable's concrete absolute path on this machine.
2. Ask the human which exact store references may expose metadata to this client.
   Do not search for stores or infer a scope from the working directory.
3. Merge only the selected registration into existing client configuration,
   preferring user scope. Use project scope only when asked. Preserve unrelated
   servers and settings; do not replace a whole configuration file.
4. Never run stash, get, import, export or other operator commands as setup. No
   value, credential environment variable or value-consuming exec wrapper is needed.
5. Ask the human to restart/reconnect the client, then verify the names-only
   tools. Registration does not authorize a hook exception or installation.

## Install

Linux/macOS, from a terminal with Python 3, curl and GitHub CLI gh installed
through a trusted package channel. gh must already be authenticated: run
`gh auth login` yourself in a private terminal, or provide `GH_TOKEN` through
your trusted credential environment without displaying it. Never paste a token
into chat, client configuration or these examples.

```sh
sh -c 'umask 077; d=$(mktemp -d) || exit
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.3.3/install.sh -o "$d/install.sh" && sh "$d/install.sh" "$@"
status=$?; rm -rf "$d"; exit "$status"' sh
```

Windows PowerShell, with gh authenticated as above and gh/curl.exe installed
through a trusted channel:

```powershell
& { $ErrorActionPreference = 'Stop'; $d = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $d | Out-Null
try { irm https://raw.githubusercontent.com/avhn/secret/v0.3.3/install.ps1 -OutFile "$d\install.ps1" -ErrorAction Stop; & (Get-Process -Id $PID).Path -NoProfile -ExecutionPolicy Bypass -File "$d\install.ps1" @args; $status = $LASTEXITCODE }
finally { Remove-Item -LiteralPath $d -Recurse -Force }; exit $status }
```

Both snippets download to a new temporary directory before running the script.
The POSIX form uses private creation permissions, runs only after curl succeeds,
and preserves download/installer status through cleanup. The PowerShell form
sets `-ErrorAction Stop` explicitly: a failed irm request throws before the
installer can run, and `finally` cleans up without converting failure to success.
It starts a child process of the same PowerShell host with `-NoProfile` and
`-ExecutionPolicy Bypass`, then returns that child's exit code after cleanup.
This bypass applies only to that one child process, allowing the downloaded file
to run under Windows PowerShell 5.1's default Restricted policy without changing
any persistent policy. Centrally enforced Group Policy can still take precedence.
Append installer flags after the final `sh` or closing PowerShell brace; both
forward them as separate arguments. Environment inputs below also work.

These commands execute an installer trusted through GitHub HTTPS, repository
ownership, tag governance and your review of that script, before payload
verification runs. A tag-pinned script is not a cryptographically verified
bootstrap. Download it into a new empty directory, review it and run it from a
separate trusted directory for stronger review, or use the trusted-checkout
procedure in [install.md](install.md).

Both installers require gh attestation verification. They verify the checksum
asset and selected binary against avhn/secret, the exact release workflow/tag,
GitHub Actions OIDC identity and hosted runners, require both attestations to
agree on the full checksum commit C, check the complete eight-record manifest,
and verify binary digest and architecture before execution/publication. Missing
gh fails; there is no checksum-only or source-build fallback.

If installation stops with
`secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry`,
authenticate gh in your own private terminal or correct its trusted environment,
then retry. Do not paste or print a token to diagnose it.

Inputs are `SECRET_VERSION` (default `0.3.3`, never latest), optional
`SECRET_RELEASE_COMMIT` (a full lowercase 40-hex C from independently authenticated
release records), and `INSTALL_DIR`. A supplied C must match verified provenance;
without it, C is derived from verified attestation identity, not a checksum field.
The scripts also accept `--version`, `--commit`, `--dir` and `--help` when run as
files. Conflicting environment/flag pins fail. Do not substitute a guessed C.

Unix installs only `~/.local/bin/secret-go` by default and does not edit PATH or
profiles. Windows installs `%LOCALAPPDATA%\Programs\secret\secret-go.exe` by
default and adds only its own directory to the user PATH. Open a new terminal to
see that PATH change. Both print the absolute executable path. Neither registers
MCP, edits client files, reads stores or installs hooks. Existing unsafe or
aliased destination directories fail rather than being silently repaired.

The standalone executable is distinct from the Bash `secret` CLI. Unlike the
trusted-checkout `bin/secret-go` launcher, it does not rehash itself before each
execution. Install/update verification is not ongoing same-user tamper protection.
Consumers do not need Go, Node, npm, Python packaging tools or lipo to run MCP;
Python 3 is needed by the Unix installer, not the installed server.

## Choose the store scope

In every example replace `/ABSOLUTE/INSTALL DIR/secret-go` with the installer's
printed absolute path, and `file:/ABSOLUTE/STORE DIR/STORE.secret` with one exact
human-approved reference. These uppercase placeholders are paths, not values.
Windows examples use `C:\ABSOLUTE\INSTALL DIR\secret-go.exe` and
`file:C:\ABSOLUTE\STORE DIR\STORE.secret`. JSON and TOML double backslashes are
syntax escaping, not literal doubled separators. Resolve paths without reading
store contents. Never put a secret value in configuration.

The real server argv is `mcp --store STORE_REFERENCE`. File references must have
absolute paths; no tilde, shell expansion, glob, inferred default or directory
scan is performed. Manual registrations can append another `--store` and one
separately approved exact reference, up to 64 distinct stores. Do not comma-join
references. The Desktop bundle accepts only one reference.

Provider references such as `libsecret:APPROVED_NAME`, `keychain:APPROVED_NAME`,
`pass:APPROVED_NAME` and `wincred:APPROVED_NAME` resolve their names-only manifests
under the normal store directory (`HOME/.secrets`, or the platform-resolved HOME
on Windows). For a nondefault manifest directory, set `SECRETS_DIR` explicitly
in the client server's environment: `env` in Desktop/Cursor/VS Code JSON,
`[mcp_servers.secret.env]` in Codex/ChatGPT TOML, `environment` in OpenCode, or
Claude Code's `--env SECRETS_DIR=ABSOLUTE_MANIFEST_DIRECTORY` before `--`.
This directory is metadata configuration, not a credential environment value.
Provider availability is platform-specific; see [Windows limits](windows.md).
`age:APPROVED_NAME` names-only outer metadata is unauthenticated and requires no
identity; do not use it to authorize value operations.

## Clients

The schemas and configuration locations below were checked against current
first-party documentation on 2026-10-28. This is documentation verification,
not real-host execution evidence or a claim that every older client version
supports the same UI. Use an up-to-date client and review startup/trust prompts.

### Claude Code

Register at user scope, with the separator before the absolute command:

```sh
claude mcp add --transport stdio --scope user secret -- "/ABSOLUTE/INSTALL DIR/secret-go" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

For PowerShell, the same client command passes Windows paths as single arguments:

```powershell
claude mcp add --transport stdio --scope user secret -- 'C:\ABSOLUTE\INSTALL DIR\secret-go.exe' mcp --store 'file:C:\ABSOLUTE\STORE DIR\STORE.secret'
```

Open `/mcp` and select secret's Reconnect action, or restart Claude Code. User
scope is stored in `~/.claude.json`; do not replace that file manually.

### Claude Desktop: bundle

The planned release asset is `secret-v0.3.3-desktop.mcpb`. Obtain it from the
exact v0.3.3 release and verify its committed checksum and attestation using the
trusted-checkout verifier in [install.md](install.md), not an adjacent checksum
alone. The registry identity is `io.github.avhn/secret`; listing/publication is
owner-gated and is not claimed here.

In Settings > Extensions > Advanced settings > Extension Developer, choose
Install Extension and select the verified bundle. Enter exactly one approved
reference in the required `store_reference` field, never a value. There is no
default or discovery. Fully quit/restart Desktop after configuration changes.
Do not also add a manual registration with the same name.

The bundle contains a macOS universal amd64/arm64 executable and Windows amd64
executable. There is no Linux Desktop bundle or Windows-on-Arm Desktop support
claim. The bundle is validated with the locked MCPB CLI and native payload smoke
tests in the release gates; actual Desktop installation, user_config
interpolation and restart behavior are not host-tested. Treat this as an opt-in
unverified host integration, not advertised extension compatibility.

### Claude Desktop: manual JSON

Use Settings > Developer > Edit Config. Merge the secret entry into
`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS, or
`%APPDATA%\Claude\claude_desktop_config.json` on Windows:

```json
{
  "mcpServers": {
    "secret": {
      "command": "/ABSOLUTE/INSTALL DIR/secret-go",
      "args": ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
    }
  }
}
```

For Windows, the equivalent entry is:

```json
{
  "mcpServers": {
    "secret": {
      "command": "C:\\ABSOLUTE\\INSTALL DIR\\secret-go.exe",
      "args": ["mcp", "--store", "file:C:\\ABSOLUTE\\STORE DIR\\STORE.secret"]
    }
  }
}
```

Fully quit Desktop, including its background/tray process, and restart it.

### Codex CLI and desktop configuration

Merge this table into `~/.codex/config.toml` (or `CODEX_HOME/config.toml` when
explicitly relocated). Do not create a duplicate table or replace other settings:

```toml
[mcp_servers.secret]
command = "/ABSOLUTE/INSTALL DIR/secret-go"
args = ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
```

Alternatively, register the same server with the CLI:

```sh
codex mcp add secret -- "/ABSOLUTE/INSTALL DIR/secret-go" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

Windows TOML uses escaped backslashes:

```toml
[mcp_servers.secret]
command = "C:\\ABSOLUTE\\INSTALL DIR\\secret-go.exe"
args = ["mcp", "--store", "file:C:\\ABSOLUTE\\STORE DIR\\STORE.secret"]
```

Restart the Codex session or desktop host after saving. Inspect its MCP server
list before using tools. This is an MCP registration, not a Codex hook trust grant.

### ChatGPT desktop

Current OpenAI documentation explicitly supports local STDIO in the ChatGPT
desktop app and shares MCP configuration with Codex CLI/IDE for the same Codex
host. Use the Codex TOML entry above, or Settings > MCP servers > Add server,
choose STDIO, and enter the same absolute command and three separate arguments.
Save and restart the desktop app. This is not a claim about older desktop builds
or a tested secret host integration.

Browser ChatGPT and remote custom-app connectors are not local stdio launchers.
They cannot use these local commands directly. Use a supported local client
instead; secret supplies no HTTP server, tunnel or remote bridge.

### OpenCode

Merge into the global `~/.config/opencode/opencode.json` (or the existing
`opencode.jsonc`). Its local server command is one array, not a shell string:

```json
{
  "mcp": {
    "secret": {
      "type": "local",
      "command": ["/ABSOLUTE/INSTALL DIR/secret-go", "mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"],
      "enabled": true
    }
  }
}
```

Restart the OpenCode session after editing and inspect its MCP connection status.

### Cursor

Merge into the user-wide `~/.cursor/mcp.json`, not a project file unless asked:

```json
{
  "mcpServers": {
    "secret": {
      "command": "/ABSOLUTE/INSTALL DIR/secret-go",
      "args": ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
    }
  }
}
```

Restart Cursor after editing and enable/review the server in its MCP settings.

### VS Code

Run MCP: Open User Configuration in the Command Palette and merge into that
profile's `mcp.json`. This is the VS Code user-profile schema, not settings.json,
`.vscode/mcp.json` workspace scope or the separate Copilot portable configuration:

```json
{
  "servers": {
    "secret": {
      "type": "stdio",
      "command": "/ABSOLUTE/INSTALL DIR/secret-go",
      "args": ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
    }
  }
}
```

Review the server trust prompt and use MCP: List Servers to restart secret after
changes. Restart the agent session if needed. Do not accept unrelated trust grants.

## Verify and understand the limits

Run the installed binary's `version` command in a terminal, using its absolute
path. Expected release output is `secret 0.3.3 (go)`. The MCP initialize response
instead identifies `secret-metadata` version `1`; health reports metadata schema
version, configured readiness and store count, not the release version.

After reconnecting, confirm the four tools `list`, `show`, `diff` and `health`.
Call health first. Only use list/show/diff on the exact references approved by
the human. Health does not prove provider availability, value validity, successful
store reads or hook protection. No tools mutate stores or return values, value
hashes or lengths; there are no resources, prompts or network listeners.

Names-only is not metadata-private: keys, labels, presence, backend, references,
paths and provider account IDs may reach the client, its model and its logs.
File metadata parsing can open local file bytes internally; provider metadata
never calls value Get. Unauthenticated age outer metadata is not integrity proof.

All four plugin/marketplace manifests are version 0.3.3, but the installed hooks
remain the Bash guard. Go hook activation is M4.1 and remains waiting sponsorship.
Installing an executable, registering MCP or passing synthetic tests does not
establish fail-closed host protection. This is accident prevention, not a sandbox.

## Update, rollback and remove

Review a new exact release and its setup guide before updating; never switch to
latest implicitly. Stop the server before replacing its executable, especially
on Windows. Re-run the reviewed version-pinned installer, retain the exact
approved references, then restart/reconnect and verify. Do not overwrite a
running binary or bypass a lock; verify stale lock ownership manually.

For rollback, install a separately verified older release to a separate absolute
path and change only the registration command after checking that release's
supported argv. Old Bash-only releases are not MCP substitutes. Keep the Bash
CLI/guard installation unchanged; no automatic fallback or Go hook cutover occurs.

To remove, stop the server, remove only its registration (or uninstall the Desktop
extension), and delete only the installed secret-go executable when no other
client uses it. Preserve other servers and settings. If desired, manually remove
the installer's Windows user PATH entry only if no remaining installation needs
it. Never delete stores, names-only manifests, recovery records or identity files.

## Sources

- [Claude Code MCP](https://code.claude.com/docs/en/mcp)
- [Claude Desktop local servers](https://modelcontextprotocol.io/quickstart/user)
- [Claude Desktop extensions](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop)
- [OpenAI local MCP, ChatGPT desktop and Codex](https://learn.chatgpt.com/docs/extend/mcp)
- [OpenCode MCP](https://opencode.ai/docs/mcp-servers/) and [global configuration](https://opencode.ai/docs/config/)
- [Cursor MCP](https://cursor.com/docs/mcp)
- [VS Code MCP configuration reference](https://code.visualstudio.com/docs/agents/reference/mcp-configuration)
