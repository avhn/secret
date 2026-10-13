# secret

Let coding agents use your credentials without reading them.

An agent with a shell can `cat .env`, run `printenv`, or grep a token out of a
config file, and the value lands in its context, its logs, and possibly a
provider's servers. `secret` gives the agent a sanctioned path instead: it sees
key names and masked lengths, picks the keys a command needs, and the values go
straight into that child process's environment.

Three parts, usable together or alone:

| Part                      | What it does                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bin/secret`              | CLI. Parses `KEY=VALUE` stores (never sources them), shows masked names, runs a child with selected keys, and redacts every loaded value from the child's stdout and stderr.                      |
| `hooks/guard-secrets`     | Claude Code `PreToolUse` hook. Denies reads of store files, environment dumps, credential printers (`gh auth token`, `security -w`, `pbpaste`, ...) and searches that would print store contents. |
| `skills/secrets/SKILL.md` | Tells the agent how to work with the CLI and how to recover from a guard denial without asking for values in chat.                                                                                |

## What this is not

**Accident prevention, not a sandbox.** It stops an agent from reading a secret
by habit or by mistake. It does not stop a determined or compromised agent with
a shell: transformed output (base64, URL encoding, substrings) is not redacted,
shell indirection the guard cannot parse is allowed unless it names a protected
file or operation, MCP search tools are not covered, and the guard makes no
decision when its input is malformed (without `jq` it denies every request).
Treat it as one layer, not the boundary.

## Install

Requirements: bash 3.2 or newer (stock macOS bash works), perl, and jq for the
guard.

The CLI:

```bash
git clone https://github.com/avhn/secret ~/.local/share/secret
ln -s ~/.local/share/secret/bin/secret ~/.local/bin/secret
```

The guard and skill, as a Claude Code plugin:

```text
/plugin marketplace add avhn/secret
/plugin install secret@secret
```

The guard allows plain `rg` because ripgrep can be told to skip store files.
Install the protective config, or merge its globs into your own:

```bash
mkdir -p ~/.config/ripgrep
cp ~/.local/share/secret/examples/ripgreprc ~/.config/ripgrep/config
export RIPGREP_CONFIG_PATH="$HOME/.config/ripgrep/config"  # in your shell profile
```

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

## Tests

```bash
bash tests/test-secret.sh   # CLI matrix, needs perl, python3 and rg
bash tests/test-guard.sh    # guard matrix, needs jq
```

Both use disposable directories and synthetic values only. CI runs them on
Linux and macOS, including stock `/bin/bash` 3.2.

## License

[GPL-3.0-or-later](LICENSE), copyright Mert Dede.
