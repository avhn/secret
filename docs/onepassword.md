# 1Password read-only scaffolding

## Status and activation gate

M5c is scaffolded, not enabled or complete. The source constant in
`internal/backend/onepassword.go` is false. Default Go registration, discovery,
metadata reads and value dispatch stay disabled. There is no environment variable,
command flag or secretstub override. Existing Bash commands, hooks and plugin
manifests are unchanged. Doctor may check executable presence, never invoke op.

Only package tests exercise the scaffolding. They build
`testdata/onepassword/fake-op.go` into a disposable directory and pass an explicit
synthetic environment, HOME, configuration and cache. They never invoke an
installed op or read a real account, store or token. The fake identity response
uses an exact single `account_uuid` field. This is a candidate synthetic contract,
not a sanitized fixture from a supported real CLI release. No interoperability
claim is made.

Before activation, the owner must supply a named licensing review, a sanitized
whoami fixture from the exact pinned 1Password CLI v2 release (2.18.0 or later),
and successful isolated provider evidence using an owner-provisioned read-only
service account and synthetic vault. Green applicable hosted CI is also required.
No authenticated CI job is configured. `TestOnePasswordIntegration` skips by
default and fails explicitly if `SECRET_REQUIRE_ONEPASSWORD=1` is requested while
these prerequisites remain unavailable. It does not contact a provider. Do not
supply authentication values in chat or enable that gate against a real store.

## Frozen registration contract (inactive)

The future human-only syntax, currently rejected by the default dispatch gate, is:

```text
secret register onepassword:NAME KEY --reference op://VAULT_ID/ITEM_ID/[SECTION_ID/]FIELD_ID --account ACCOUNT_UUID --auth service-account [--label N=V]
```

There is no provider call at registration. Session authentication, signin, unlock,
item discovery, attachments, OTP retrieval, provider writes and export workflows
are out of scope. Authentication must be provisioned outside agents. Do not pass
a token as an argument or store it in a manifest.

Registration requires terminal stdin and stdout, opens the controlling terminal,
and requires the exact hidden challenge showing target, key, canonical labels,
reference, account UUID and authentication mode. Validation precedes rendering;
confirmation precedes destination filesystem access. Registration is not a
writable operator action: import/export/rotate/rename/delete acceptance remains
unchanged. A separate names-only `register` audit action includes target, key and
labels only, not provider coordinates. Audit persistence remains explicit opt-in
through the feature API; the inactive register CLI does not enable it implicitly.

Vault, item and account IDs must each be 26 lowercase ASCII letters or digits.
Field and optional section IDs have 1 to 64 ASCII letters, digits, underscores
or hyphens, starting with a letter, digit or underscore. Titles, links, dot
segments, percent escapes, interpolation, queries, fragments, controls and
option-like input are rejected. Moving an item fails the registered lookup; there
is no fallback search. Duplicate identities, IDs and exact references are rejected.
Existing identities cannot be retargeted. A manifest is pinned to one account.

## Container and compatibility

Use a dedicated Go `SECRETS_DIR` when this feature eventually activates. The
names-only manifest is `NAME.onepassword-keys`, outside Bash `*.keys` discovery:

```text
secret-manifest-v2
backend=onepassword
{"key":"API_KEY","labels":{},"id":"0123456789abcdef0123456789abcdef","provider":{"reference":"op://vvvvvvvvvvvvvvvvvvvvvvvvvv/iiiiiiiiiiiiiiiiiiiiiiiiii/password","account_uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaa","auth":"service-account"}}
```

Headers and each canonical JSON record end in LF. Property order and JSON
serialization match the example; labels use lexically sorted JSON keys. No extra,
unknown, duplicate or missing fields, trailing JSON, null labels or future-provider
extension maps are accepted. Limits are 1 MiB per document, 16 KiB per record
(excluding LF), 1024 records, 128 labels per record and 256 bytes per key. Existing
key and label grammars also apply. Local IDs are random 32-lowercase-hex strings.
Metadata JSON keeps its current version and calls this local ID `account`, never
the provider account UUID. It excludes the reference and authentication metadata.

Reads require private regular files and no-follow opening; Unix files are 0600,
and writes use the existing shared lock and private atomic replacement. Windows
has parser and metadata tests only; private registration and transport are
unsupported. No v1 grammar is weakened and no migration is automatic. Mixed-store
tests prove unchanged Bash still discovers file and v1 stores, ignoring v2.

## Read and failure behavior

The inactive bound opener freezes a validated manifest snapshot, absolute
PATH-resolved executable and provider environment for the invocation. It resolves
only registered local IDs within the exact service. A single 60-second CLI read
budget covers requested stores and account checks. Each process also has a
15-second cap, 1 MiB per captured stream and 250 ms pipe-drain bound. The Unix
provider starts a detached session with EOF stdin and no controlling terminal;
process-group cancellation also addresses pipe-holding descendants.

Only an inherited service-account token is accepted. Connect settings and session
settings are rejected. OP configuration is filtered and biometric unlock, debug
and cache are forced off. The same executable/environment performs the bounded
identity check and `op read --no-newline REFERENCE`, with no shell, whole-item
JSON, output file, retry or automatic signin. Identity is checked once before
reads and must match the pinned account. Missing or ambiguous identity fails.

Values remain owned byte buffers, never argv, errors, JSON or audit. Stderr and
rejected stdout are cleared. Empty values, NUL, CR, any LF (even one terminal LF),
ASCII edge whitespace and matching surrounding single or double quotes fail.
Normalization must produce exactly the raw bytes; no newline stripping is
allowed. The legacy stash normalizer is unchanged. Failures return fixed safe
errors, never provider diagnostics or exec error text.

`run` loads every registered record in each requested store, including unselected
and overridden records, before launching the child. The existing literal filter
covers all loaded values on both streams, including chunk boundaries. Ambient
unselected names are removed. A missing record, provider error or exhausted budget
aborts before child launch; earlier owned buffers are cleared. Get/clip fetch only
the selected record. Get remains human-terminal-only; exec remains unfiltered
and agent-denied. Hook regression tests retain direct, wrapped and quoted op-read,
revealing item-get and registration denials without an internal-provider exception.

Put/Delete, stash, import targets, both export directions and lifecycle commands
return `onepassword backend is read-only` before value input, source reads,
provider calls, audit setup, recovery or lock creation, including secretstub
builds. Names-only metadata, completion and MCP use projections of the manifest,
never provider enumeration or value calls. Their public read path remains gated;
tests exercise the private metadata reader and supplied metadata independently.

## Limits of the evidence

Run `python3 -I tests/test-onepassword.py` with Go 1.27.3 for offline schema,
fake-op and composed CLI coverage, followed by a detached-provider assertion under
a real PTY parent. Native Ubuntu and macOS CI run this explicitly. Windows retains
parser/metadata coverage and rejects execution. Cross-vet is not native evidence.

Synthetic tests do not establish real account authentication, actual rate-limit
semantics, licensing, interoperability or host fail-closed behavior. Coverage is
registered-fields-only, not the rest of a vault or transformed values. Trusted
PATH and a safe inherited environment are operator responsibilities. Inherited
service-account tokens can reach launched children and are not automatically
added to the redaction set. Values can change between separate reads, and loading
all records amplifies rate limits. CLI schema drift, stale IDs and account
confusion remain activation-review concerns. Byte clearing is best effort, not
secure erasure. This is accident prevention, not a sandbox.
