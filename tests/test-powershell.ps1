# Test-only native oracle driver. Candidate sources are parsed, never executed.
# Invoke this committed script with the edition being tested. No CLI build,
# install, host configuration, provider access or model calls occur here.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Desktop', 'Core')]
    [string]$Edition,
    [Parameter(Mandatory = $true)]
    [string]$Oracle
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native oracle evidence requires Windows' }
if (-not [IO.Path]::IsPathRooted($Oracle) -or -not (Test-Path -LiteralPath $Oracle -PathType Leaf)) {
    throw 'Oracle must name an existing absolute executable'
}
if ($PSVersionTable.PSEdition -ne $Edition) { throw 'Driver running in wrong PowerShell edition' }
$version = $PSVersionTable.PSVersion
if ($Edition -eq 'Desktop') {
    if ($version.Major -ne 5 -or $version.Minor -ne 1) { throw 'Inbox oracle must be Windows PowerShell 5.1' }
} elseif ($version.ToString() -ne '7.6.7') {
    throw 'Core oracle must be exactly PowerShell 7.6.7'
}
$current = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
if (-not [string]::Equals([IO.Path]::GetFullPath($current), [IO.Path]::GetFullPath($Oracle), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Driver executable differs from requested oracle'
}
Write-Output ('Oracle edition={0} version={1} executable={2}' -f $Edition, $version, $Oracle)
Write-Output ('OS={0} runner_image={1} image_os={2}' -f [Environment]::OSVersion.VersionString, $env:ImageVersion, $env:ImageOS)
$env:GOTOOLCHAIN = 'local'
$env:SECRET_PS_ORACLE = $Oracle
$env:SECRET_PS_ORACLE_REQUIRED = '1'
# Each oracle batch has a bounded count/byte protocol, capture and watchdog
# (30 seconds startup plus 250 ms per extra source, capped at two minutes).
# The test-suite limit does not change hook read/analysis/overall deadlines.
$failed = $false
go test -v -count=1 -timeout 45m ./internal/hook/ps -run '^Test(Oracle|Differential)'
if ($LASTEXITCODE -ne 0) { $failed = $true }
# Record independent path controls even if a grammar comparison failed. These
# are classifier calls only, not execution of candidate PowerShell commands.
go test -v -count=1 ./internal/hook -run '^TestPowerShell(Native|Production)'
if ($LASTEXITCODE -ne 0) { $failed = $true }
if ($failed) { exit 1 }
