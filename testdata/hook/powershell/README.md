# PowerShell oracle fixtures (M5e)

Synthetic PowerShell sources and expectations for the staged Go hook's PowerShell
subset. Nothing here is executed: oracles only parse and statically bind source with
`[System.Management.Automation.Language.Parser]::ParseInput` and
`[System.Management.Automation.Language.StaticParameterBinder]::BindCommand`.

Candidate pins (step 1, to be verified with checksums in step 4):

| Edition | Version | Source |
| --- | --- | --- |
| Windows PowerShell Desktop | 5.1 (inbox) | windows-latest image `win25-vs2026 20261021.278.1` |
| PowerShell Core | 7.6.7 | official GitHub release zip, pinned by SHA-256, not the runner's preinstalled copy |

Support claims cover only verified pins. A runner image or pin change needs renewed
oracle evidence. See [the M5e plan](../../../docs/design/m5e-plan.md).
