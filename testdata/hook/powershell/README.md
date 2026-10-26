# PowerShell oracle fixtures (M5e)

Synthetic PowerShell sources and expectations for the staged Go hook's PowerShell
subset. Nothing here is executed: oracles only parse and statically bind source with
`[System.Management.Automation.Language.Parser]::ParseInput` and
`[System.Management.Automation.Language.StaticParameterBinder]::BindCommand`.

Oracle pins (asset verified 2026-10-26; native runtime evidence still requires CI):

| Edition | Version | Source |
| --- | --- | --- |
| Windows PowerShell Desktop | major 5, minor 1 (inbox) | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` on windows-latest |
| PowerShell Core | exactly 7.6.7 | official `PowerShell-7.6.7-win-x64.zip`, never the runner's preinstalled copy |

The [official v7.6.7 release](https://github.com/PowerShell/PowerShell/releases/tag/v7.6.7)
asset API digest and `hashes.sha256` list this zip's SHA-256 as
`d2f952ebdbf24386cb8923553aa58e41a846db35a6155ea04c58142a4b16dbb7`.
Downloading the zip into a fresh empty temporary directory and running
`sha256sum` independently produced the same digest. CI pins that digest in
`.github/workflows/ci.yml`, verifies before extraction, and keeps download and
extraction directories separate from the checkout and committed scripts.

The `powershell oracle (Desktop)` and `powershell oracle (Core)` jobs print
`ImageOS`, `ImageVersion`, the OS build, Go version, full PowerShell version and
absolute executable path. These logs, with their workflow run URL and revision,
record the actual mutable windows-latest image, not an assumed image pin. The
step 1 discovery image was `win25-vs2026 20261021.278.1`; it is not proof of the
image used by a later run. Support claims cover only versions with passing native
evidence. A runner image or pin change needs renewed oracle evidence.

`cases.jsonl` is the classified synthetic corpus. `replay.jsonl` is mandatory
replay input, initially grammar controls, not invented native golden results.
Every Go-accepted source from both files must match native tokens, AST structure,
bindings and modeled command metadata. Default aliases are queried independently
using [`AliasInfo.Definition`](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.aliasinfo.definition),
before any metadata lookup or static binding can load their target modules.
`ResolvedCommand` is not assumed to be non-null. The SDK API applies to both the
5.1 reference assemblies and 7.x. The documented nullable `ScriptRequirements`
and `EndBlock` properties remain guarded; `CleanBlock` is inspected only when
that property exists. Fixed cmdlet discovery must provide nonempty parameter
sets, otherwise the script reports a fixed infrastructure failure.
The fixed-seed generation pass tests 2,000 inputs per edition by default;
`SECRET_PS_ORACLE_BUDGET` accepts 1..20000 for local experiments. Reducing it does
not replace the CI default. A failure prints the original synthetic source and a
bounded, minimized JSON replay row. Add the row to `replay.jsonl` before fixing a
mismatch; never change an expectation to conceal an allow. Candidates are never
executed, and tests never automatically modify tracked fixtures.

`SECRET_PS_ORACLE` must name an absolute executable. Missing configuration skips
clearly for local Go tests; `SECRET_PS_ORACLE_REQUIRED=1` makes absence a failure.
A configured but missing or broken oracle always fails, including process failure,
malformed/incomplete JSON, oversized output, binding exceptions and timeouts.
Each fresh no-profile process reads one UTF-8 JSON array of 1..250 source
strings, at most 8 MiB including JSON escaping, with a 40 KiB UTF-8 limit per
source. The runner partitions by both bounds without dropping or reordering
inputs. The script writes one JSON array of indexed records:
`{"index":0,"projection":{...},"error":null}` or
`{"index":0,"projection":null,"error":{"id":"RuntimeException","line":42}}`.
Each source is projected in its own try/catch; an error prevents acceptance at
that index without suppressing other results. Fixed cmdlet metadata is shared
within a batch; candidate text is never executed and cannot mutate session state.
Single-source comparisons use a batch of one, including mismatch minimization.

The process-tree watchdog allows 30 seconds startup plus 250 ms per additional
source, capped at two minutes. Stdout capture scales from 4 MiB per source up to
64 MiB per batch; stderr is capped at 4 KiB. Failure, timeout, malformed JSON,
count/order mismatch, missing fields (including nested and nullable fields) and
per-index errors fail closed. Script-level diagnostics contain fixed text plus
sanitized error identifiers and oracle-script line numbers only. The Go runner
includes stderr on process failure only when it is at most 512 bytes of printable
ASCII (apart from the final CRLF/LF). No exception messages, candidate text or
environment contents are diagnostic fields. HOME, USERPROFILE, LOCALAPPDATA and
APPDATA point to the disposable oracle directory, allowing module caches to be
reused across batches without inheriting user state.

These are test-only budgets, distinct from the unchanged two-second hook analysis
budget. The 2,000-input CI budget, job layout and suite/job timeouts are unchanged.
Synthetic helper faults exercise the runner without PowerShell installed. Native
path controls and classifier p99/40 KiB measurements are printed in the required
job. A symlink-creation skip or absent 8.3 support is reported explicitly, and the
8.3 log names the actual fixture volume rather than assuming C: or D:.
Neither syntax evidence nor the test-only adapter enables production allows or
proves real-host failure blocking. See [the M5e plan](../../../docs/design/m5e-plan.md).
