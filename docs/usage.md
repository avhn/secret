# Usage and workflows

For installation and names-only MCP registration, start with [setup](setup.md).

## Stores, providers and labels

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
The Go CLI includes [native Windows clipboard support](windows.md#native-clipboard-unreleased),
including best-effort history/cloud exclusion requests. Unix clipboard providers
are unchanged; no installed-default or Windows hook permission changes are implied.
The staged Go CLI caps clipboard values at 16 MiB and attempts an immediate
conditional clear if timer setup fails after copying.

Run `secret help` for the full reference, including exit statuses.

## Operator commands and templates

These commands are implemented in the Go CLI. Both installed guards remain
on Bash. For a development build, use
`go build -o /absolute/private/build/secret ./cmd/secret`.
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
hook exception. See [Windows support](windows.md) for platform and lifecycle
limits. No installed-host protection is claimed.
See [CONTRIBUTING.md](../CONTRIBUTING.md) for gates and [the M3 plan](design/m3-plan.md)
for the implementation contract.

## Encrypted age stores

M5d adds explicit `age:NAME` encrypted file stores on Linux/macOS, with reviewed
`filippo.io/age v1.3.2`, whole-store authenticated reads and ciphertext-only
atomic writes. `age-init` is create-only and `age-rekey` verifies the new identity
before publication; both require real terminals and exact target confirmation.
Key files must be private under `HOME/.secrets/.age-keys/`, and value-consuming
commands require explicit `--age-identity FILE`. Names-only interfaces need no
identity, but their outer metadata is unauthenticated. Use `list --backend age`;
default discovery and the Bash CLI are unchanged. Windows age filesystem
operations remain unsupported even though M5a's separate Windows CLI gate passed.
See [age setup, migration, recovery and limits](age.md). M5d passed its hosted
gate in PR #28; this does not activate hooks or authorize publication.

## 1Password scaffolding (inactive)

The staged Go implementation includes test-only read-only 1Password scaffolding.
Default registration, discovery and reads are disabled pending isolated provider
evidence and licensing review. There is no environment switch to enable it.
The Bash CLI, installed hooks and plugin manifests are unchanged. See
[the contract and limitations](onepassword.md); do not point the Bash CLI at
a Go v2 manifest.
