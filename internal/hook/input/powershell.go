package input

// PowerShell has separate request budgets. Do not shrink the shared Bash, file
// or patch envelope bounds when applying the pending PowerShell contract.
const (
	MaxPowerShellEnvelopeBytes = 64 << 10
	MaxPowerShellSourceBytes   = 40 << 10
)
