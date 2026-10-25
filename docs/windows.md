# Windows support (staged Go CLI)

The staged Go CLI implements native Windows amd64 development support, verified
on hosted windows-latest runners; this is not a Windows release or installation
claim. The installed defaults remain the Bash CLI and guard, and installed
manifests are unchanged. See [installation and rollback](install.md) and the
[M5a implementation and evidence plan](design/m5a-plan.md).

## Supported behavior

| Area | Windows behavior |
| --- | --- |
| Stores | File stores and `wincred:NAME` backed by native Credential Manager calls. |
| Inventory | `SECRETS_DIR/NAME.wincred-keys` is a names-only v1 manifest; recovery uses `NAME.wincred-keys.recovery`. The suffix stays outside unchanged Bash `*.keys` discovery. Metadata operations do not fetch credentials. |
| Console | Human operator consent and hidden input use verified `CONIN$`/`CONOUT$` console handles. Redirected operator stdin/stdout and stash stdin are rejected before store/provider discovery. Console modes are restored on catchable exits. |
| Children | `run` filters both output streams; `exec` supervises an unfiltered child rather than replacing the process. Both use native Job containment. |
| Private files | Templates, audit, stores, locks, scratch and recovery use handle-checked, protected owner-only DACLs. |
| File/patch hooks | Native checks retain protected paths across UNC and administrative shares, subst drives, junctions and resolvable 8.3 aliases, with public-file controls and ambiguous-path denial. |

Use the staged executable directly in your own terminal for value entry and
operator actions. Values do not belong in argv or chat. `get` is human-terminal-only
and rejects redirected output; it is not an agent retrieval route. `exec` is
unfiltered and is only for human or configured-launcher use, not agent transport.
For filtered child output, use `run` with a file or `wincred:NAME` reference.

Credential Manager access uses registered exact generic targets
`secret/NAME/ACCOUNT`, not provider enumeration. Records persist for the current
user on the local machine, not through enterprise roaming. `run` loads every
registered value before launch, including unselected accounts, and aborts if any
fetch fails. It removes inherited registered keys before exporting the selection
and redacts all loaded literals from stdout and stderr.

Children and descendants are enrolled atomically at creation in a non-inheritable
kill-on-close Job, with no breakaway or unenrolled fallback. Setup failure aborts
before execution. Normal completion, cancellation, timeout and output/filter
failure terminate remaining Job members with bounded cleanup. Windows `run` and
`exec` have a 15-second runtime deadline. No implicit shell is inserted; executable
lookup uses the child PATH/PATHEXT, without implicit current-directory search.

Templates are private rendered files; successful containment precedes their
removal. Audit remains private and names-only, not a value log. Neither feature
changes the human-consent or agent-denial boundaries.

## Limits and hook behavior

- ACL checks require current-user ownership and a protected owner-only DACL,
  not Unix mode bits. Broad or NULL DACLs and ACL-incapable filesystems are not
  silently accepted; arbitrary existing parents are not repaired. These ACLs do
  not isolate administrators or another process running as the same user.
- Data flushes and real publication errors remain required, but Windows directory
  flushing provides no power-loss durability guarantee. Killed writers leave a
  tokened `.write-lock` for manual owner verification and removal, never automatic
  stealing. Provider mutation and manifest publication are not jointly atomic;
  names-only recovery is not permission to blindly delete provider records.
- Literal-output redaction covers UTF-8 and UTF-16LE/BE, not other code pages or
  transformed values. Values that cannot round-trip through the Windows UTF-16
  environment, NUL and case-insensitive name collisions fail before child creation.
- Age filesystem operations, pass and 1Password provider operations remain
  unsupported on Windows. Clipboard parity is outside M5a.
- The Windows hook denies every shell call with a fixed denial, including public
  commands. It does not parse PowerShell or CMD as Bash. A Windows PowerShell
  adapter belongs to conditional M5e; CMD remains denied.
- Native file/patch checks are bounded decision-time metadata proofs, not a
  filesystem-race sandbox. 8.3 coverage depends on short-name availability.
- `hooks/guard-go.cmd` is development-only, invokes its fixed sibling
  `hooks/secret.exe`, and exits 2 when that binary is missing. No installed
  manifest references it. It is not a verified release launcher.
- Hosts may skip hooks or fail to start them and may fail open. No Windows host
  evidence establishes fail-closed protection. Synthetic tests, cross-builds and
  a working development shim do not establish installed protection.

## Hosted verification gate

The [M5a tracker](../ROADMAP.md#m5a-windows-cli-and-credential-manager) links the
green hosted run. It covers the native Windows package job and the isolated CLI
job: cmd and PowerShell matrices with stdin, redaction, ACL and shim checks,
required UNC loopback, junction and subst fixtures, ConPTY console, Job and
storage tests, and independent exact CredMan cleanup and absence verification.
The hosted fixture volume had no 8.3 short names, so short-alias handling has
synthetic coverage only and no native evidence. Cross-vet and compilation on
another OS are not native runtime evidence. No installed-default promotion or
host protection is claimed here.
