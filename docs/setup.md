# Set up secret MCP

This is the canonical setup guide for the opt-in secret local stdio MCP server.
v0.5.0 is prepared and unreleased. Install, choose exact references, register,
reconnect and verify in that order. See [installation](install.md) for pins and
checkout verification and [release approvals](release.md) for publication status.

## Paste to your agent

```text
Follow https://github.com/avhn/secret/blob/v0.5.0/docs/setup.md to install and register secret MCP; ask me for the exact intended store references, never discover or read stores, handle values, run operator consent commands, or bypass a guard.
```

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

Install or update to the latest release.

Linux/macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/avhn/secret/v0.5.0/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/avhn/secret/v0.5.0/install.ps1 | iex
```

The script defaults to the latest release, resolved once from GitHub's release
redirect, then downloads only that explicit tag. No GitHub account, gh, Python
or credentials are required. Unix needs POSIX sh, curl, standard GNU/BSD utilities
and sha256sum or shasum. Windows needs PowerShell 5.1 or 7 and curl.exe.
Install dependencies through trusted channels.

Set `SECRET_VERSION` to a strict release version (optional leading `v`) to pin
or roll back. File invocations also accept `--version V`, `--dir DIR` and
`--help`; conflicting environment and flag pins fail. `INSTALL_DIR` selects the
destination. For `irm | iex`, set `SECRET_VERSION` and `INSTALL_DIR` in that
PowerShell process, rather than appending file parameters. `--commit` and
`SECRET_RELEASE_COMMIT` were removed and fail with a link to checkout verification
in docs/install.md. No installer changes execution policy.

Unix defaults to `~/.local/bin/secret` and does not edit PATH or profiles.
Windows defaults to `$HOME\.local\bin\secret.exe`, with the native user profile
as fallback when HOME is absent, and adds only its install directory to user
PATH once. Open a new terminal afterward. Both print the concrete executable
path. Neither reads stores, registers MCP, installs hooks or edits clients.

Rerunning updates to latest. Under the tokened lock, a matching installed digest
is a no-op that preserves file identity, mtime and Windows PATH. Otherwise a new
binary is downloaded, checksum/format/architecture/version-checked and atomically
published. The existing executable is never run. Explicit pins permit rollback;
a corrupt safe installation is repaired. Verification failures preserve the old
file. Unsafe ownership, writable ancestors, aliases, reparse points and DACLs are
rejected, not repaired. Locks are never stolen. Stop clients before replacement,
especially on Windows where an open executable can block atomic replacement.

The one-liners trust GitHub HTTPS, repository/tag governance and the script before
payload verification. `curl | sh` cannot guarantee a complete download before
execution; the function wrapper mitigates truncation, but is not a complete-download
guarantee. A pinned script URL does not pin the default binary release. Download
and review the script first, or use the stronger trusted-checkout route.
HTTPS checksums detect corruption, not a compromised release publisher. The
standalone installers do not verify attestations or provenance and do not rehash
themselves on each run. They have no offline or source-build fallback.

For optional manual provenance verification, install gh separately and run
`gh attestation verify FILE --repo avhn/secret` on the downloaded asset. This does
not by itself establish the full source-S/checksum-C boundary. The stronger
[checkout verification](install.md#release-and-platform-pins) below pins an
independently authenticated C and checks the release workflow, tag and inventory.

Final CLI names and destinations described below ship from **v0.4.0 onward**.
The download snippets select latest by default; explicit version pins select a release, not main. The published
v0.3.4 installer uses `secret-go` on Unix and
`%LOCALAPPDATA%\Programs\secret\secret-go.exe` on Windows, not the final paths.
Use the printed executable path for that release; do not infer the installed
name from the checkout documentation. Update release pins together in the coordinated identity bump; never replace
published assets or tags.

From v0.4.0 onward, Unix installs only `~/.local/bin/secret` by default and does not edit PATH or
profiles. Windows installs `$HOME\.local\bin\secret.exe` by
default, falls back to the native user profile when HOME is absent, and adds only
its own directory to the user PATH. Open a new terminal to
see that PATH change. Both print the absolute executable path. Neither registers
MCP, edits client files, reads stores or installs hooks. Existing unsafe or
aliased destination directories fail rather than being silently repaired.

The standalone executable and checkout launcher both run the Go CLI.
Bash rollback is explicit at `compat/secret`, never a bootstrap fallback. Unlike the
trusted-checkout `bin/secret` launcher, it does not rehash itself before each
execution. Install/update verification is not ongoing same-user tamper protection.
Consumers do not need Go, Node, npm, Python packaging tools or lipo to install
the standalone CLI or run MCP.

## Migrate an earlier installation

From v0.4.0 onward, re-register each MCP client with the new installer's printed
`secret` / `secret.exe` path, preserving the approved store references and other
arguments. Restart clients and verify the new registration before removing the
old `secret-go` / `secret-go.exe` file. Review each old path first; do not delete
an unknown or custom executable. On Windows, remove the old
`%LOCALAPPDATA%\Programs\secret` user PATH entry only after confirming no other
installation uses it. Installers do not delete old binaries, remove old PATH
entries, or rewrite MCP registrations automatically. See [rollback](install.md#explicit-bash-rollback).

## Choose the store scope

In every example replace `/ABSOLUTE/INSTALL DIR/secret` with the installer's
printed absolute path, and `file:/ABSOLUTE/STORE DIR/STORE.secret` with one exact
human-approved reference. These uppercase placeholders are paths, not values.
Windows examples use `C:\ABSOLUTE\INSTALL DIR\secret.exe` and
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
claude mcp add --transport stdio --scope user secret -- "/ABSOLUTE/INSTALL DIR/secret" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

For PowerShell, the same client command passes Windows paths as single arguments:

```powershell
claude mcp add --transport stdio --scope user secret -- 'C:\ABSOLUTE\INSTALL DIR\secret.exe' mcp --store 'file:C:\ABSOLUTE\STORE DIR\STORE.secret'
```

Open `/mcp` and select secret's Reconnect action, or restart Claude Code. User
scope is stored in `~/.claude.json`; do not replace that file manually.

### Claude Desktop: bundle

The planned release asset is `secret-v0.5.0-desktop.mcpb`. Obtain it from the
exact v0.5.0 release and verify its committed checksum and attestation using the
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
      "command": "/ABSOLUTE/INSTALL DIR/secret",
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
      "command": "C:\\ABSOLUTE\\INSTALL DIR\\secret.exe",
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
command = "/ABSOLUTE/INSTALL DIR/secret"
args = ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
```

Alternatively, register the same server with the CLI:

```sh
codex mcp add secret -- "/ABSOLUTE/INSTALL DIR/secret" mcp --store "file:/ABSOLUTE/STORE DIR/STORE.secret"
```

Windows TOML uses escaped backslashes:

```toml
[mcp_servers.secret]
command = "C:\\ABSOLUTE\\INSTALL DIR\\secret.exe"
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
      "command": ["/ABSOLUTE/INSTALL DIR/secret", "mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"],
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
      "command": "/ABSOLUTE/INSTALL DIR/secret",
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
      "command": "/ABSOLUTE/INSTALL DIR/secret",
      "args": ["mcp", "--store", "file:/ABSOLUTE/STORE DIR/STORE.secret"]
    }
  }
}
```

Review the server trust prompt and use MCP: List Servers to restart secret after
changes. Restart the agent session if needed. Do not accept unrelated trust grants.

## Verify and understand the limits

Run the installed binary's `version` command in a terminal, using its absolute
path. Expected release output is `secret 0.5.0 (go)`. The MCP initialize response
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

All four plugin/marketplace manifests are version 0.5.0, but the installed hooks
remain the Bash guard. Go hook activation is M4.1 and remains waiting sponsorship.
Installing an executable, registering MCP or passing synthetic tests does not
establish fail-closed host protection. This is accident prevention, not a sandbox.

## Configured value-consuming launchers

This separate, opt-in example is not the names-only secret MCP server above.
Windows long-lived exec shipped in v0.3.4 and is included in the pinned release
above; see the [Windows exec contract](design/windows-exec-plan.md). Unix exec
remains unchanged.
Resolve the installer's printed absolute executable path, replacing the command
placeholder below only with that concrete path after an approved update. Replace
STORE with an explicit human-approved absolute file path. `exec -f` takes a
plain path, not a `file:` reference. Configuration
contains key names, never values; do not discover stores or add this as an agent
retrieval route. Keep unrelated servers and settings.

Illustrative Unix configuration, using the same absolute-path placeholders as
above and a distinct server name:

```json
{
  "mcpServers": {
    "openproject-launcher": {
      "command": "/ABSOLUTE/INSTALL DIR/secret",
      "args": ["exec", "-f", "/ABSOLUTE/STORE DIR/STORE.secret", "--key", "OPENPROJECT_API_TOKEN", "--optional-key", "X", "--", "uvx", "openproject-ce-mcp@0.4.1"]
    }
  }
}
```

Windows JSON preserves each argument and escapes backslashes, not a shell string:

```json
{
  "mcpServers": {
    "openproject-launcher": {
      "command": "C:\\ABSOLUTE\\INSTALL DIR\\secret.exe",
      "args": ["exec", "-f", "C:\\ABSOLUTE\\STORE DIR\\STORE.secret", "--key", "OPENPROJECT_API_TOKEN", "--optional-key", "X", "--", "uvx", "openproject-ce-mcp@0.4.1"]
    }
  }
}
```

This launcher consumes selected values in the third-party server's environment.
Its output is unfiltered and can disclose values; the server owns its protocol,
output and EOF handling. Windows file-backed stdio is inherited directly and has
no runtime deadline. On orderly shutdown the host closes stdin, the server exits,
and secret performs checked Job cleanup. A server ignoring EOF or blocked on
output can remain alive indefinitely: after its shutdown budget the host must
terminate the wrapper. Killing only an intermediary host need not kill secret.
Consoleless signal delivery is not guaranteed. See [Windows limits](windows.md).

Synthetic argv, protocol and lifecycle tests establish no real Claude Code,
Codex or OpenCode compatibility, startup, reconnect or shutdown behavior. That
requires separate versioned real-host evidence. This example grants no hook
exception and does not change agent-denial rules or installed defaults.

## Update, rollback and remove

Rerun either one-liner to update to the latest release. Review release changes
and stop the server first, especially on Windows. Matching installed bytes are
left untouched. Retain the exact approved references, then restart/reconnect and
verify. Do not bypass a lock; verify stale lock ownership manually.

Set `SECRET_VERSION` (or use `--version` when running the script as a file) for
an explicit pin or rollback. Pins skip latest resolution and may replace a newer
version. A separate `INSTALL_DIR` lets you review an older release before changing
the registration path. Check that release's supported argv. Old Bash-only releases
are not MCP substitutes. Keep the Bash CLI/guard installation unchanged; no
automatic fallback or Go hook cutover occurs.

To remove, stop the server, remove only its registration (or uninstall the Desktop
extension), and delete only the installed secret executable when no other
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
