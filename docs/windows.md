# Windows support (staged Go CLI)

M5a's staged Go CLI gate passed on native Windows amd64 hosted runners (PR #29,
run [40246119003](https://github.com/avhn/secret/actions/runs/40246119003)). The
v0.3.2 packaging work adds raw `secret-v0.3.2-windows-amd64.exe` and
`secret-v0.3.2-windows-arm64.exe` assets plus `install.ps1`; native candidate and
public-release installs on both architectures remain separate required evidence.
This document does not claim those new installs have passed or publication exists.
The installed defaults remain Bash CLI/guard. Plugin manifests become 0.3.2
without Go hook activation, which stays M4.1, waiting sponsorship.
See [MCP setup](setup.md), [installation and rollback](install.md) and the
[M5a implementation and evidence plan](design/m5a-plan.md).

## Release installation and MCP

The version-pinned PowerShell bootstrap snippet is in [setup.md](setup.md#install).
It needs gh and curl.exe from trusted channels. gh must already be authenticated:
run `gh auth login` yourself in a private terminal, or supply `GH_TOKEN` through
your trusted credential environment without displaying it. Never paste a token
into chat or client configuration. Verification checks checksum/binary
attestations, exact workflow/tag identity, their common C, digest and PE machine.
`SECRET_RELEASE_COMMIT` optionally pins a separately authenticated full C;
missing gh never falls back to checksums. Executing the bootstrap script still
trusts GitHub HTTPS, tag governance and the reviewed script before verification.

The download completes with `-ErrorAction Stop` before the snippet starts a
child process of the current PowerShell host using `-NoProfile -ExecutionPolicy
Bypass -File`. This bypass applies only to that one child process, not persistent
policy, so Windows PowerShell 5.1's default Restricted policy does not block the
downloaded file. Centrally enforced Group Policy can still take precedence.
`finally` cleans up and the saved child exit code is propagated afterward.

If the installer reports
`secret: GitHub CLI is not authenticated; run gh auth login or set GH_TOKEN, then retry`,
authenticate gh privately or correct its trusted environment, then retry. Do not
paste or print a token to troubleshoot it.

The default destination is `%LOCALAPPDATA%\Programs\secret\secret-go.exe`.
`INSTALL_DIR` / `--dir` overrides it; `SECRET_VERSION` / `--version` defaults to
0.3.2, never latest; `--commit` supplies the optional full C and `--help` explains
inputs. It adds only its own directory to user PATH. It does not modify client
files, register MCP, install hooks or overwrite a Bash installation. Use the
printed absolute path, not an assumed PATH lookup. The raw executable does not
perform the Unix checkout launcher's per-exec rehash. Cold offline Windows
installation is unsupported; do not bypass attestation for an air-gapped machine.

Stop clients before replacement. Open-image failures preserve the old executable;
there is no delete-first/copy fallback. Private destination and tokened locking
checks reject unsafe ACLs/reparse points and never steal stale locks.

Local MCP uses exactly `mcp --store STORE_REFERENCE`; Windows file references
are absolute, for example `file:C:\ABSOLUTE\STORE DIR\STORE.secret`.
Names-only provider metadata resolves registered manifests, never value Get.
The Desktop MCPB includes Windows amd64 only; Windows arm64 CLI availability is
not a Desktop-on-Arm compatibility claim. Locked MCPB CLI and native subprocess
smoke validation do not prove actual Desktop installation/configuration/restart.
MCP metadata may expose names, labels, paths and provider account IDs to clients
and models, never values, hashes or lengths. It grants no hook exception.

Full bundle assembly runs on macOS with lipo, Go 1.26.10, Node 26.10.0,
npm 11.19.1 and Python 3.14.8, not on an end user's Windows installation.
The narrowly reviewed build-only Zod exception and fresh audit gate are described
in [release tooling security](release.md#packaging-tools-and-advisory-review) and
`scripts/package_mcpb.py`; it is not a runtime dependency in the bundle.

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
  commands. It does not parse PowerShell or CMD as Bash. M5e steps 1 to 4 have
  native PowerShell 5.1/7.6.7 parser evidence, but the adapter remains unwired;
  steps 5 and 6 are waiting sponsorship. Production PowerShell/CMD allows are
  not enabled by the parser tests or this release.
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
