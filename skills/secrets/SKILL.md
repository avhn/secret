---
name: secrets
description: >
  Use API tokens, credentials, .env stores, auth headers, deploy keys, or "use my
  token" requests without reading secret values into context. Discover masked key
  names, select a child environment, and recover from secret-guard denials.
argument-hint: "[list | show FILE | use FILE KEY]"
---

# Secrets

Never read stores, echo, transform, retrieve, or inspect secret values. Use the
`secret` CLI so values reach the command that needs them without entering this
conversation. This is accident prevention, not a vault or a sandbox.

## Workflow

1. `secret list` discovers default store paths without opening them.
2. `secret show FILE` shows key names, masked lengths, canonical sorted labels,
   duplicate warnings, and ignored line numbers. With selectors, it shows the
   selected record per key or `<unset>`. It parses, never sources. Bare `NAME`
   resolves to `~/.secrets/NAME.secret`, then `~/.secrets/.NAME.secret`.
3. Select explicit files and keys. Later `-f` files override earlier ones.
   Missing required or empty keys fail. Missing optional keys are not exported.
   Exact `[env=dev,region=eu]` headers scope following assignments; `[]` resets
   to unlabeled. Use `--env dev` (alias for `--label env=dev`) and repeated
   `--label name=value` on `show`, `stash`, `get`, `clip`, `run`, or `exec`.
   Most-specific matching labels win; equal-specificity ties fail. Without
   selectors, only unlabeled records qualify. `stash` changes the exact label
   set, not all matching records. Labeled stores are not plain dotenv for other
   tools, and older `secret` versions read every section as one flat store.
4. When a key is missing, ask the user to run `secret stash FILE KEY` in their
   own terminal and type the value at the hidden prompt. Never request a value
   in chat, and do not ask them to send it back.

## Examples

Pass headers on stdin rather than exposing values in the child's argv:

```bash
secret run -f ~/.secrets.env --key API_TOKEN -- bash -c \
  'printf "Authorization: Bearer %s\n" "$API_TOKEN" | curl -fsS -H @- https://api.example.test/status'
```

Any command can receive a selected environment:

```bash
secret run -f github --key GH_TOKEN -- gh repo view
secret run -f ~/.secrets.env --key DATABASE_URL -- npm run migrate
```

MCP server launchers configured by the user (never agent Bash commands) use
unfiltered `exec`, which preserves JSON-RPC framing:

```bash
exec secret exec -f ~/.secrets.env --key SERVICE_TOKEN -- npx -y some-mcp-server
```

Use `secret clip FILE KEY` only on an explicit user request for the clipboard.
`secret get` is for a human at a terminal, never an agent operation.

## Denial recovery

| Denied operation                          | Safe next step                                              |
| ----------------------------------------- | ----------------------------------------------------------- |
| Tool access or patch of a protected store | Use masked `show`; the user stashes changes                 |
| Credential printer or clipboard read      | Human pipes it directly to `secret stash FILE KEY`          |
| `security ... -g` (also with a pipe)      | Human uses `-w` piped directly into `stash`                 |
| `secret get` or `secret exec`             | Use filtered `secret run`                                   |
| Recursive grep or unrestricted rg         | Use plain `rg PATTERN DIR` with the protective config       |
| Grep content/count tree with secrets      | Use `files_with_matches` or narrow to a safe file/directory |
| Missing key                               | Ask the user to stash it privately                          |

Do not disguise a command, disable a hook, or change permissions to get past a
denial. Template files (`.env.example`, `.env.sample`, `.env.template`) outside
`~/.secrets` are readable; the protective rg config excludes `.env.*`
entirely, so use an explicit-file read for templates.

## Limits

`run` redacts every nonempty loaded literal value, including short values, on
separate stdout and stderr streams, with bounded chunk buffering. It cannot
catch base64, URL encoding, substrings, or other transformations. Values never
enter `secret`'s own or its filter's argv. A child that interpolates a value into
its own argv can expose it to the local process list; prefer stdin or header
files. `exec` is intentionally unfiltered and preserves stdio, status, and
signals.

The guard hook is heuristic. Missing jq denies nonempty requests; malformed
input or analysis failure naming no protected file or operation receives no
decision. Hosted and MCP search tools are not covered. A deliberately malicious
agent with a shell is out of scope.
