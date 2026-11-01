# Windows support (staged Go CLI)

M5a's staged Go CLI gate passed on native Windows amd64 hosted runners (PR #29,
run [40246119003](https://github.com/avhn/secret/actions/runs/40246119003)). The
The v0.4.1 test-fixture patch retains raw `secret-v0.4.1-windows-amd64.exe` and
`secret-v0.4.1-windows-arm64.exe` assets plus `install.ps1`; native candidate and
public-release installs on both architectures remain separate required evidence.
This document does not claim those new installs have passed or publication exists.
The final CLI is `secret.exe`; installed hooks remain the Bash guard.
Plugin manifests become 0.4.1
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

The snippet installs its pinned release, not main. Published v0.3.4 installs `%LOCALAPPDATA%\Programs\secret\secret-go.exe`; use its
printed path. After upgrading, re-register MCP and manually retire reviewed
old binaries and obsolete user PATH entries as described in [setup](setup.md#migrate-an-earlier-installation).

From v0.4.0 onward, the default destination is `$HOME\.local\bin\secret.exe`, with the native user
profile as fallback when HOME is absent. Unsafe ancestors, including a
CodexSandboxUsers Modify ACE, remain rejected without permission repair.
Only the CLI name changes: Claude and Codex keep the Bash guard, and native
hook activation remains deferred. Explicit Bash rollback requires Git Bash:
`bash /absolute/trusted/checkout/compat/secret`. No automatic fallback occurs.
`INSTALL_DIR` / `--dir` overrides it; `SECRET_VERSION` / `--version` defaults to
0.4.1, never latest; `--commit` supplies the optional full C and `--help` explains
inputs. It adds only its own directory to user PATH. It does not modify client
files, register MCP or install hooks. From v0.4.0 onward, verified atomic
publication intentionally replaces a safe existing final-name executable. Use the
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

Full bundle assembly runs on macOS with lipo, Go 1.27.3, Node 26.10.0,
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
| Private files | Store files, templates, audit, locks, scratch and recovery use handle-checked, protected owner-only DACLs. Store parents use the trusted-principal rule below. |

| Clipboard (unreleased) | `clip` uses native Unicode clipboard APIs and a detached, pipe-fed conditional clearer. No PowerShell or external clipboard utility is used. |
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
failure terminate remaining Job members with bounded cleanup. Windows `run`
retains its 15-second runtime deadline. The unreleased `exec` change below removes
only exec's runtime deadline. No implicit shell is inserted; executable lookup
uses the child PATH/PATHEXT, without implicit current-directory search.

Templates are private rendered files; successful containment precedes their
removal. Audit remains private and names-only, not a value log. Neither feature
changes the human-consent or agent-denial boundaries.

## Long-lived configured exec launchers (unreleased)

The [Windows exec plan](design/windows-exec-plan.md) narrowly supersedes M5a's
historical exec deadline/output-failure contract, not its run contract. This is
unreleased behavior, not available through the pinned installer release above.
See the separate [configured-launcher example](setup.md#configured-value-consuming-launchers-unreleased),
which requires the installer's concrete absolute path and an explicitly approved
store, and is distinct from names-only `mcp --store`.

When both outputs supplied to the Go CLI are non-nil files, exec inherits stdin,
stdout and stderr through the existing restricted duplicated handle list. No
CLI-owned output pipes, decoding, filtering or protocol text intervene. The
wrapper waits indefinitely for its direct child, not EOF or descendant lifetime.
Successful direct-child exit still requires checked Job cleanup, terminating and
waiting on pinned remaining member identities; pipe-holding descendants alone
do not turn that exit into a drain failure. Native uint32 status is preserved on
the supported 64-bit CLI. An observed signal returns `128 + signal`; launch,
wait or cleanup failure takes precedence with status 1. Overlapping relay, wait
and cleanup failures share one bounded fixed diagnostic; direct and relay launch
failures use the same fixed native messages.

Direct exec cannot observe child output failures and has no two-second stalled
writer protection or inherited-pipe drain. Broken pipes and backpressure belong
to the server: an error-ignoring or blocked server can remain alive indefinitely.
Non-file output writers, including mixed file/buffer callers of `cli.Main`, relay
both supplied streams without a runtime deadline, retaining two-second writer
protection, output-error cancellation and the 250 ms inherited-pipe drain. Their
exec-only two-second shutdown bound starts on cancellation escalation or output
failure and reaches checked Close without requiring another wait notification.
Caller-owned files stay open; invalid or typed-nil handles fail before execution,
without substituting global streams. Run, importers and templates stay bounded.

The first observed interrupt starts a two-second grace period, with scoped
CTRL_BREAK forwarding; repeated signals do not extend it. Escalation terminates
the Job and enters checked cleanup, without an indefinite separate wait. Detached
or consoleless hosts have no console-event delivery guarantee. Synthetic signal
channels do not prove detached-host signal delivery.

Graceful shutdown is server-owned: the host closes stdin, the server handles EOF
and exits, then secret cleans remaining Job members. Secret does not consume stdin
to detect host disappearance, watch parent lifetime or probe output. Killing an
intermediary host need not terminate the wrapper. For an EOF-ignoring server, the
host must terminate secret after its shutdown budget. Wrapper death closes its
sole kill-on-close Job handle and triggers kernel containment, but cannot run Go
defers, report cleanup status or promise application cleanup. An enclosing host
Job may help but requires host-specific evidence.

Value byte buffers are cleared before exec and the native UTF-16 environment
block is cleared after creation, before waiting. Go environment string copies
remain GC-managed and cannot be securely erased. Output is unfiltered and may
expose values. Synthetic detached lifecycle tests establish neither Claude Code,
Codex nor OpenCode startup/reconnect/shutdown compatibility, nor hook protection.
Versioned real-host sessions and applicable hosted Windows CI remain separate
evidence gates; installed defaults and every agent-denial rule are unchanged.

## Native clipboard (unreleased)

The staged Go CLI supports `secret clip FILE KEY [SECONDS]` on Windows, with
existing selectors, exit statuses and the `copied KEY; clears in Ns if
unchanged` message. The default timeout remains 45 seconds, and zero requests
an immediate conditional clear. Unix pbcopy, wl-copy and xclip providers are
unchanged. The staged Go CLI now rejects values larger than 16 MiB before
copying on every platform. Its clearer reads into one bounded allocation and
zeros the full allocation on success and input failures. If timer setup fails
after copying, the caller immediately attempts a conditional clear before
returning the unchanged setup error. This extension is outside the historical
M5a gate and still needs its own hosted CI run; it is not available in the
pinned installer release above.

The writer retries a busy clipboard with bounded exponential backoff (ten open
attempts, about 800 ms total sleep). It publishes `CF_UNICODETEXT` through
movable Windows-owned memory. UTF-8 values are converted directly from byte
buffers to UTF-16LE byte buffers, without Go value strings; owned intermediate
buffers are zeroed. Invalid UTF-8 and embedded NUL are rejected with a fixed
copy error before changing the clipboard, rather than silently replacing or
truncating the value. Other text, including non-BMP characters and line
endings, is preserved.

The clearer receives the value through a private inherited pipe, never argv,
environment, files, logs, audit or JSON. It detaches from the parent console
and survives normal CLI exit without retaining stdout/stderr pipes. After the
timeout it compares the current Unicode text with the original value and
terminating NUL, then empties the clipboard only on an exact match. Comparison
and emptying share one open clipboard session, so a concurrent replacement
cannot be cleared between them. Copying a different value preserves it;
copying the identical text again still counts as unchanged.

The helper first requests `CREATE_BREAKAWAY_FROM_JOB`, allowing it to outlive
an ancestor Job only when that Job permits breakaway. An `ERROR_ACCESS_DENIED`
launch retries once without breakaway, using a fresh command and the same
input pipe. Other errors do not retry. This does not change any enclosing Job
policy. In particular, this repo's Windows `run` and `exec` children are in a
kill-on-close Job that does not permit breakaway: a clip invocation inside
that Job uses the fallback, and parent cleanup can terminate its clearer
before the timeout, leaving the value on the clipboard. Host-created Jobs may
impose the same limit. Invoke clip directly from a human terminal outside such
Jobs when the detached timer is needed; even there it remains best effort.
Busy/unavailable clipboards, helper termination, logout and shutdown can also
prevent clearing. There is no persistent timer, retry service or
secure-erasure guarantee.

The writer registers the [Windows exclusion formats][formats]:
`ExcludeClipboardContentFromMonitorProcessing`, plus
`CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard` with DWORD
zero, before publishing text. Failure to publish these requests aborts the
copy. Cooperating Windows history/cloud consumers can honor them, but this
does not prove exclusion on every Windows version or configuration, revoke
earlier copies, or stop third-party managers, remote desktop redirection or
another same-session reader. The value is exposed to the clipboard and its
consumers; the timeout cannot erase copies already taken or guarantee removal
from memory.

[formats]: https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats

Use clip only for an explicit human clipboard request. This change does not
add an agent retrieval route, loosen any hook decision or certify installed
host protection. The existing Windows hook still denies shell calls, and
clipboard reads remain prohibited agent behavior.

Synthetic interface tests never touch the clipboard. The native round-trip and
post-exit tests require `SECRET_REQUIRE_WINDOWS_CLIPBOARD=1`, GitHub Actions
Windows metadata and `RUNNER_ENVIRONMENT=github-hosted`. They run only on the
disposable hosted runner, require an initially empty clipboard under the open
clipboard lock, and leave pre-existing nonempty contents untouched by failing
before mutation. They use only disposable synthetic text, conditionally clean
it up and verify the clipboard is empty afterwards. Do not enable this gate
locally.

## Limits and hook behavior

- Store files require current-user ownership and a protected owner-only DACL,
  not Unix mode bits. A store parent must be owned by the current user, must not
  be a reparse point, and must have a non-NULL, non-empty DACL containing only
  ordinary allow ACEs for that user, SYSTEM (`S-1-5-18`) or Administrators
  (`S-1-5-32-544`). Explicit and inherited ACEs and unprotected parent DACLs are
  accepted. Any other principal, including read-only grants, Users, Everyone,
  Authenticated Users or custom sandbox groups, is rejected. Deny, conditional
  and unsupported ACEs are rejected too. Existing ACLs are never repaired.
- Templates, audit, locks, scratch, recovery files and newly created directories
  retain protected owner-only DACLs. The store-parent exception does not apply
  to template or audit directories. ACL-incapable filesystems are not accepted.
  These ACLs do not isolate administrators or processes running as the same user.
- Doctor reports `private` for protected owner-only objects, `trusted_parent`
  for directories accepted only by the store-parent rule, and `insecure` for
  rejected DACLs. This Windows status distinction corrects the former false
  insecure classification; it does not certify template/audit eligibility.
  Doctor artifact checksums remain public-file checks with resolved-parent
  semantics, not store-parent ownership or DACL checks.
- Data flushes and real publication errors remain required, but Windows directory
  flushing provides no power-loss durability guarantee. Killed writers leave a
  tokened `.write-lock` for manual owner verification and removal, never automatic
  stealing. Provider mutation and manifest publication are not jointly atomic;
  names-only recovery is not permission to blindly delete provider records.
- Literal-output redaction covers UTF-8 and UTF-16LE/BE, not other code pages or
  transformed values. Values that cannot round-trip through the Windows UTF-16
  environment, NUL and case-insensitive name collisions fail before child creation.
- Age filesystem operations, pass and 1Password provider operations remain
  unsupported on Windows. Native clipboard support above is a separate unreleased
  extension, not evidence from the historical M5a gate.
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
