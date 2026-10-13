# Security model

`secret` is accident prevention for coding agents. It keeps credential values
out of an agent's context when the agent reaches for them by habit or mistake:
`cat .env`, `printenv`, `gh auth token`, a content search over a directory
holding a store. It is **not a sandbox** and does not contain an agent that is
deliberately trying to read a secret.

## What it protects

- **Store values never pass through the CLI's own argv or diagnostics.** `show`
  and `list` print names, masked lengths and paths only. `run` delivers
  selected keys through the child's environment and replaces every loaded value
  with `<redacted>` on the child's stdout and stderr. If a redaction filter
  fails, `run` stops the child and exits 1 rather than printing unfiltered
  output.
- **Writes are private and atomic.** `stash` reads values from a hidden prompt
  or stdin, writes the replacement inside a private 0700 directory, and renames
  it onto the store under a lock. It refuses symlinked and non-regular targets.
- **The guard denies the common accidents** before a tool call runs: reading
  store files and well-known credential files (cloud CLI credentials, Docker
  and gh config, npmrc, pypirc, SSH private keys, `/proc/*/environ`), dumping
  the environment, credential printers (`gh auth token`, `gcloud auth
print-access-token`, `aws configure get`, `op read`, `pass`, `secret-tool`,
  `security -w`, clipboard readers), and content searches over trees that hold
  protected files. Protected paths are matched after brace and `$IFS`
  expansion and through symlink aliases, and unknown commands may not take a
  protected file as an input; metadata commands (`ls`, `stat`, `chmod`, `rm`,
  `git check-ignore`) and env-file consumers (`docker --env-file`,
  `node --env-file`, `dotenv -e`) stay allowed. A printer piped straight into
  `secret stash FILE KEY` is allowed, since the value goes into a store instead
  of the output.

## What it does not protect

These are outside the threat model. Reports about them are welcome as
documentation or hardening suggestions, but they are not vulnerabilities:

- **Transformed output.** Redaction matches literal values. Base64, URL
  encoding, hex, substrings, reversed or split values are not caught.
- **Shell indirection the guard cannot resolve statically.** The guard
  tokenizes commands and never evaluates them. Variables set elsewhere, files
  of commands, `eval`, aliases, functions, interpreters reading paths from
  their input, and other dynamic constructs can name a protected file without
  spelling it. The guard denies an unresolved operand only when the command
  text itself names something protected.
- **What env-file consumers do with values.** `docker run --env-file .env`,
  `node --env-file=.env` and `dotenv -e .env -- CMD` are allowed. Obvious
  printing children (`env`, `printenv`, `docker compose config`) are denied,
  but an arbitrary program given those values can still print them.
- **Executable substitution.** The guard trusts command names. A different
  program named `secret`, `cat` or `jq` earlier on PATH is not detected.
- **Tools the guard does not see.** The hook covers Claude Code's Bash, Read,
  Grep, Edit and Write tools. MCP servers, other agents and other editors are
  not covered.
- **Process-level visibility.** A child that puts a value in its own argv
  exposes it to the local process list. Descendants a `run` child leaves
  running are not supervised. Any process running as the same user can read
  the stores and, while a child runs, its environment.
- **Fail-open inputs.** The guard makes no decision when its input is not
  valid JSON, or when analysis fails on text that names no protected file or
  operation. Without `jq` it denies every request instead.
- **Ignored dependency trees.** A content search over a tree skips `.git` and
  `node_modules` unless `--hidden`, a glob or an explicit path brings them
  into scope, so a protected file inside them is not detected.
- **Clipboard consent.** `secret clip` is allowed for agents because the value
  never reaches their output; the skill limits it to explicit user requests,
  which a hook cannot verify.
- **Searches without the protective ripgrep config.** Plain `rg` is treated as
  safe only when the effective ripgrep config excludes store files (see
  `examples/ripgreprc`) and adds no option that widens what is read;
  otherwise content searches over trees holding protected files are denied.

## Reporting

Use GitHub's private vulnerability reporting on this repository for anything
that lets a value reach agent output through a path the guard or the CLI
claims to cover. Describe the command or tool call and the observed decision.
**Never include a real credential**; synthetic values like `synthetic-token`
reproduce every case the test suites cover.
