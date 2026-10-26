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
bindings and modeled command metadata. Default aliases are queried independently.
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
Per-case capture is bounded to 4 MiB stdout and 4 KiB stderr with a 15-second
process-tree watchdog, distinct from the unchanged two-second hook analysis
budget. Synthetic helper faults exercise the runner without PowerShell installed.
Native path controls and classifier p99/40 KiB measurements are printed in the
required job. A symlink-creation skip or absent 8.3 support is reported explicitly.
Neither syntax evidence nor the test-only adapter enables production allows or
proves real-host failure blocking. See [the M5e plan](../../../docs/design/m5e-plan.md).
