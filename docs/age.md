# Opt-in age stores (staged Go CLI)

M5d adds encrypted-at-rest stores to the staged Go CLI on Linux and macOS.
It does not replace the Bash CLI, change plaintext defaults, activate Go hooks,
change plugin manifests or authorize a release. Native hosted CI remains the
milestone gate. Windows builds and tests the codec but rejects age filesystem
operations before opening paths, pending M5a.

## References and key provisioning

An explicit `age:NAME` reference maps to `SECRETS_DIR/NAME.secret.age` (normally
`HOME/.secrets/NAME.secret.age`). Names use the same simple grammar as provider
references. Bare names still mean plaintext `.secret` files. Default `list` and
Bash discovery never discover age stores; use `list --backend age` explicitly.
An age envelope passed as a plaintext file reference is rejected, not parsed as
an empty dotenv file.

Provision keys yourself using a trusted human-operated tool. The CLI does not
generate keys, escrow them, discover identities or use an identity environment
variable. Keep backups under your own key-management policy. Losing every
matching identity makes the ciphertext unrecoverable.

Identity and recipient files must be explicit absolute paths under the private
`HOME/.secrets/.age-keys/` namespace. That namespace is already covered by the
hook path policy. Directories must be owned by the current user and 0700; files
must be owned, regular and 0600 or stricter. Every path component is anchored
and aliases, including ancestor symlinks, are rejected. Existing permissions
are never silently repaired. Human setup can create the namespace with
`mkdir -m 700` before provisioning files; `age-init` also explicitly initializes
missing private directories, only after confirmation.

Files contain one native X25519 identity or canonical recipient per line.
Empty lines and lines beginning with `#` are ignored; CRLF is accepted. Each
file is capped at 64 KiB and 32 distinct entries. SSH, plugin, hybrid,
post-quantum, scrypt and passphrase keys or recipients are unsupported.
Recipients are public but integrity-sensitive and get the same path protection.
Never paste private keys or credential values into a chat or agent command.

## Human-operated workflows

Invoke the staged Go binary directly in your own terminal, not through an
agent tool. Substitute your absolute key-file paths in these examples. No key
material or credential value belongs in argv.

```sh
secret-go age-init age:team \
  --age-recipients "$HOME/.secrets/.age-keys/team.recipients" \
  --age-identity "$HOME/.secrets/.age-keys/team.identity"
secret-go stash --age-identity "$HOME/.secrets/.age-keys/team.identity" age:team TOKEN
secret-go show age:team
secret-go show --format=json age:team
secret-go list --backend age
secret-go run --age-identity "$HOME/.secrets/.age-keys/team.identity" \
  -f age:team --key TOKEN -- ./consumer
secret-go age-rekey age:team \
  --age-identity "$HOME/.secrets/.age-keys/team.identity" \
  --age-recipients "$HOME/.secrets/.age-keys/next.recipients" \
  --age-new-identity "$HOME/.secrets/.age-keys/next.identity"
```

`age-init` and `age-rekey` require both stdin and stdout terminals, then hidden
exact confirmation of the action and target, for example `age-init age:team`.
There is no `--yes`, piped confirmation or operator JSON. Init is create-only
under the anchored lock and refuses any existing target without reading its
bytes. Ordinary writes and rekey require an initialized, existing target.
Both init and rekey decrypt and fully verify the candidate with the supplied
identity before publication. Every configured matching identity can decrypt;
a removed identity fails on the new file, but old ciphertext remains readable
with old identities. Rekey does not erase old copies or backups.

`--age-identity FILE` is accepted only by value-consuming commands: stash, get,
clip, run/exec, import/export and lifecycle. Names-only show, JSON, diff,
completion and explicitly allowlisted metadata MCP need no identity. They
expose names, labels and stable account identifiers, not ciphertext sizes,
recipients, hashes or value lengths. Their outer metadata is unauthenticated
and must never be used as authorization.

Run decrypts every age record, including unselected values, before starting
any child. Those values join the literal redaction set, and every loaded name
is removed from inherited environment variables before selection. A failed
identity or authentication aborts before spawn. Mixing age, plaintext and
provider references retains the usual later-file precedence. Age plus
`--template-file` is rejected before decryption to avoid persisting decrypted
age values through templates. Exec remains unfiltered and restricted to human
or configured-launcher use; the accident-prevention boundary is unchanged.

Import keeps its existing `dotenv:ABS_PATH`, `op:ID` and `bw:ID` source grammar
and can target an initialized age store. Age sources use export to another
initialized age store or a provider. Export requires `--on-conflict=fail`;
both transfers are insert-only and consent-gated. No age-to-plaintext route is
supported, including `import --from age:NAME --into file:...`. Confirmed source
key and label identities are reselected on the authenticated snapshot; selection
drift aborts before destination mutation. Sources are left untouched, with no
erasure claim. Lifecycle rename preserves stable accounts; rotation and rekey
do too.

Audit remains off unless `--audit-dir ABS_PATH` is supplied. Init and rekey
record only their action, target and outcome, plus schema/time fields. No
identity path, recipient list, fingerprint, ciphertext size or value appears
in an event. New operator commands remain human-only; hook denials are not
relaxed.

## Envelope and transaction guarantees

The bounded binary v1 envelope contains `secret-age-store-v1\n`, a big-endian
u32 metadata length, sorted canonical X25519 recipients, a canonical names-only
`backend=age` manifest, then one binary age stream. Limits are 1 MiB metadata,
18 MiB envelope, 16 MiB dotenv plaintext and 1,024 key/label identities.
The decrypted payload contains a version prefix, SHA-256 binding of the exact
outer framing and metadata, and a length-delimited warning-free, duplicate-free
dotenv payload that must match the manifest exactly. Value consumers read the
whole stream to authenticated EOF and reject truncation and trailing data.
Neither library errors nor partial plaintext cross the backend boundary.

Under the shared tokened `.write-lock`, writes reread and authenticate,
recheck identities and conflicts, mutate in memory, encrypt and verify the
complete candidate, then write ciphertext only to marked private scratch.
File sync precedes anchored rename. Age requires directory sync after rename;
a failure there reports uncertain durability, never rollback. Failures before
rename leave the old file unchanged. There is no plaintext temp file, backup
or journal.

After SIGKILL, the tokened lock and possibly marked ciphertext scratch remain.
Never steal that lock or automatically roll forward. A human must verify the
writer is no longer running and manually remove the stale lock. The next lock
owner cleans only recognized marked scratch. Never blindly remove unrelated
directories. The synthetic crash suite demonstrates this recovery protocol,
not arbitrary power-loss behavior on every filesystem.

## Security limits

The core `filippo.io/age v1.3.2` library is pinned and license/security reviewed
in [the M5d plan](design/m5d-plan.md). No executable, plugin, subprocess prompt
or PATH-selected crypto tool is used. Only native X25519 recipients are allowed.

Encryption protects values at rest, not visible names, labels, recipients or
approximate file size. The binding detects corruption and substitution, not
replay of an older valid envelope or sender authorship. There is no key escrow,
rollback prevention or secure-erasure guarantee. Application-owned plaintext
and key-file buffers are byte slices and are cleared on every path. The age
identity parser requires an immutable Go string and exposes no wipe API;
library/runtime copies, garbage collection, swap and core dumps limit cleanup.
A malicious same-user process and a determined agent are outside the model.
No synthetic test establishes installed-host fail-closed protection.
