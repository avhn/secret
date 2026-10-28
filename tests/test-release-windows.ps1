#Requires -Version 5.1
<#
Native release payload evidence on disposable hosted Windows runners only.
Candidate mode copies the integrated candidate, not a locally rebuilt binary; it
is not provenance evidence. Published mode uses the real standalone installer.
Both modes use synthetic file stores, never CredMan, real stores or host hooks.
Run separately in native Windows PowerShell 5.1 and PowerShell 7; no silent skips.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $Assets,
    [Parameter(Mandatory)][ValidateSet('amd64', 'arm64')][string] $ExpectedArchitecture,
    [switch] $Published,
    [string] $Tag = 'v0.3.0',
    [string] $Commit = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$version = '0.3.0'
$checkout = Split-Path -Parent $PSScriptRoot
$utf8 = New-Object Text.UTF8Encoding($false)

function Assert-True([bool] $Condition, [string] $Name) {
    if (-not $Condition) { throw "Windows release assertion failed: $Name" }
}

Assert-True ($env:OS -eq 'Windows_NT' -and $env:GITHUB_ACTIONS -eq 'true' -and
    $env:RUNNER_OS -eq 'Windows') 'native disposable hosted Windows required'
Assert-True ([IO.Path]::IsPathRooted($Assets) -and (Test-Path -LiteralPath $Assets -PathType Container)) 'absolute candidate input'
Assert-True ($Tag -ceq 'v0.3.0') 'exact release tag'
Assert-True (-not (Get-Item -LiteralPath (Join-Path $checkout '.secret-release-test-fixture') -Force -ErrorAction SilentlyContinue)) 'no shipped fixture marker'

# OS architecture and process architecture must both be native. In particular,
# an emulated amd64 PowerShell on Arm is not Arm release evidence.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SecretReleaseNative {
    [StructLayout(LayoutKind.Sequential)]
    public struct SystemInfo {
        public ushort Architecture, Reserved;
        public uint PageSize;
        public IntPtr Minimum, Maximum, Mask;
        public uint Processors, Type, Granularity;
        public ushort Level, Revision;
    }
    [DllImport("kernel32.dll")]
    public static extern void GetNativeSystemInfo(out SystemInfo info);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process2(IntPtr process, out ushort machine, out ushort native);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();
}
'@
$info = New-Object SecretReleaseNative+SystemInfo
[SecretReleaseNative]::GetNativeSystemInfo([ref]$info)
$expectedCpu = if ($ExpectedArchitecture -eq 'amd64') { 9 } else { 12 }
$expectedMachine = if ($ExpectedArchitecture -eq 'amd64') { 0x8664 } else { 0xaa64 }
[UInt16]$processMachine = 0
[UInt16]$nativeMachine = 0
Assert-True ([SecretReleaseNative]::IsWow64Process2([SecretReleaseNative]::GetCurrentProcess(),
    [ref]$processMachine, [ref]$nativeMachine)) 'native architecture query succeeds'
Assert-True ($info.Architecture -eq $expectedCpu -and $nativeMachine -eq $expectedMachine -and
    $processMachine -eq 0) 'OS and PowerShell process match target without emulation'
Write-Output ('OS=' + [Environment]::OSVersion.VersionString + ' arch=' + $ExpectedArchitecture +
    ' ImageOS=' + $env:ImageOS + ' ImageVersion=' + $env:ImageVersion +
    ' RUNNER_ARCH=' + $env:RUNNER_ARCH + ' PowerShell=' + $PSVersionTable.PSVersion.ToString())

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$identity.Dispose()
$root = Join-Path $env:RUNNER_TEMP ('secret release ' + [Guid]::NewGuid().ToString('N'))
$script:Value = 'synthetic-release-' + [Guid]::NewGuid().ToString('N')
$script:Work = $root

function Protect-Path([string] $Path, [bool] $Directory) {
    $acl = if ($Directory) { New-Object Security.AccessControl.DirectorySecurity } else { New-Object Security.AccessControl.FileSecurity }
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = if ($Directory) { [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [Security.AccessControl.InheritanceFlags]::None }
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid,
        [Security.AccessControl.FileSystemRights]::FullControl, $inheritance,
        [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
    $null = $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Assert-Private([string] $Path) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'no reparse install path'
    $acl = Get-Acl -LiteralPath $Path
    Assert-True ($acl.AreAccessRulesProtected -and
        $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $sid.Value) 'protected current-owner DACL'
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-True ($rules.Count -gt 0) 'nonempty DACL'
    foreach ($rule in $rules) {
        Assert-True ($rule.IdentityReference.Value -eq $sid.Value -and -not $rule.IsInherited -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'explicit owner-only access'
    }
}

# Installers may retain SYSTEM/Administrators access to public executables.
# Synthetic stores below still require the stricter owner-only storage DACL.
function Assert-InstallAcl([string] $Path, [bool] $Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    Assert-True (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'no reparse installed object'
    $acl = Get-Acl -LiteralPath $Path
    Assert-True ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $sid.Value) 'current-user install owner'
    if ($Directory) { Assert-True $acl.AreAccessRulesProtected 'protected install directory DACL' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    Assert-True ($rules.Count -gt 0) 'nonempty install DACL'
    foreach ($rule in $rules) {
        Assert-True ($rule.IdentityReference.Value -in @($sid.Value, 'S-1-5-18', 'S-1-5-32-544') -and
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow) 'no untrusted install access'
    }
}

function New-PrivateDirectory([string] $Path) {
    $null = [IO.Directory]::CreateDirectory($Path)
    Protect-Path $Path $true
    Assert-Private $Path
}

function Write-PrivateFile([string] $Path, [string] $Text) {
    [IO.File]::WriteAllText($Path, $Text, $utf8)
    Protect-Path $Path $false
}

# Windows CRT quoting, also supported by .NET Framework/PowerShell 5.1, which
# lacks ProcessStartInfo.ArgumentList. Script text and values never enter argv.
function Quote-Argument([string] $Text) {
    Assert-True (-not $Text.Contains($script:Value)) 'synthetic value absent from argv'
    $quoted = New-Object Text.StringBuilder
    $null = $quoted.Append('"')
    $slashes = 0
    foreach ($character in $Text.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            $null = $quoted.Append(('\' * (2 * $slashes + 1)))
        } else {
            $null = $quoted.Append(('\' * $slashes))
        }
        $slashes = 0
        $null = $quoted.Append($character)
    }
    $null = $quoted.Append(('\' * (2 * $slashes)))
    $null = $quoted.Append('"')
    return $quoted.ToString()
}

function Assert-NoValue([byte[]] $Bytes) {
    foreach ($encoding in @($utf8, [Text.Encoding]::Unicode, [Text.Encoding]::BigEndianUnicode)) {
        Assert-True (-not $encoding.GetString($Bytes).Contains($script:Value)) 'no synthetic value in output'
    }
}

function Invoke-Captured([string] $Image, [string[]] $Arguments, [string] $InputText = '') {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Image
    $start.Arguments = (($Arguments | ForEach-Object { Quote-Argument $_ }) -join ' ')
    $start.UseShellExecute = $false
    $start.WorkingDirectory = $script:Work
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    # Prevent inherited store/feature configuration from selecting real inputs.
    foreach ($name in @($start.EnvironmentVariables.Keys)) {
        if ($name -like 'SECRET_*' -or $name -like 'SECRETS_*') { $start.EnvironmentVariables.Remove($name) }
    }
    foreach ($name in @('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'XDG_CACHE_HOME', 'GH_CONFIG_DIR', 'TEMP', 'TMP')) {
        $start.EnvironmentVariables[$name] = Join-Path $root $name
    }
    $start.EnvironmentVariables['SECRETS_DIR'] = Join-Path $root 'absent stores'
    $start.EnvironmentVariables['GH_PROMPT_DISABLED'] = '1'
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $stdout = New-Object IO.MemoryStream
    $stderr = New-Object IO.MemoryStream
    $started = $false
    try {
        $started = $process.Start()
        Assert-True $started 'native process starts'
        $copyOut = $process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $copyErr = $process.StandardError.BaseStream.CopyToAsync($stderr)
        $bytes = $utf8.GetBytes($InputText)
        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(240000)) { $process.Kill(); throw 'Windows release process timeout' }
        Assert-True ([Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($copyOut, $copyErr), 10000)) 'bounded output drain'
        Assert-True ($stdout.Length -lt 1MB -and $stderr.Length -lt 1MB) 'bounded output size'
        $got = [pscustomobject]@{ Code = $process.ExitCode; Out = $stdout.ToArray(); Err = $stderr.ToArray() }
        Assert-NoValue $got.Out
        Assert-NoValue $got.Err
        return $got
    } finally {
        if ($started -and -not $process.HasExited) { $process.Kill(); $process.WaitForExit() }
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

function Assert-Pe([string] $Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    Assert-True ($bytes.Length -gt 64 -and $bytes[0] -eq 0x4d -and $bytes[1] -eq 0x5a) 'DOS image header'
    $offset = [BitConverter]::ToUInt32($bytes, 0x3c)
    Assert-True ($offset -le $bytes.Length - 6) 'bounded PE header offset'
    Assert-True ([BitConverter]::ToUInt32($bytes, $offset) -eq 0x4550 -and
        [BitConverter]::ToUInt16($bytes, $offset + 4) -eq $expectedMachine) 'native PE machine matches OS'
}

function Hash([string] $Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-Version([string] $Image) {
    $got = Invoke-Captured $Image @('version')
    Assert-True ($got.Code -eq 0 -and $got.Err.Length -eq 0 -and
        $utf8.GetString($got.Out) -ceq "secret $version (go)`n") 'exact release version'
}

$userPathKey = $null
$userPath = $null
$userPathKind = $null
if ($Published) {
    $userPathKey = Get-Item -LiteralPath 'HKCU:\Environment'
    $userPath = $userPathKey.GetValue('Path', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($null -ne $userPath) { $userPathKind = $userPathKey.GetValueKind('Path') }
}
try {
    New-PrivateDirectory $root
    foreach ($name in @('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'XDG_CACHE_HOME', 'GH_CONFIG_DIR', 'TEMP', 'TMP')) {
        New-PrivateDirectory (Join-Path $root $name)
    }
    $asset = "secret-v$version-windows-$ExpectedArchitecture.exe"
    $contract = Get-Content -LiteralPath (Join-Path $checkout 'testdata/plugin/contracts.json') -Raw | ConvertFrom-Json
    $manifest = ''
    foreach ($name in $contract.assets) {
        $path = Join-Path $Assets $name
        Assert-True (Test-Path -LiteralPath $path -PathType Leaf) 'complete integrated candidate'
        $manifest += (Hash $path) + '  ' + $name + "`n"
    }
    Assert-True ($contract.assets.Count -eq 8 -and
        [IO.File]::ReadAllText((Join-Path $Assets "checksums-v$version.txt")) -ceq $manifest) 'exact eight-entry candidate manifest'
    $destination = Join-Path $root 'installed binary with spaces'
    $binary = Join-Path $destination 'secret-go.exe'
    $shell = (Get-Process -Id $PID).Path
    $installer = Join-Path $checkout 'install.ps1'
    $installArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $installer,
        '--version', $version, '--commit', $Commit, '--dir', $destination)
    if ($Published) {
        Assert-True ($Commit -cmatch '^[0-9a-f]{40}$') 'authenticated full checksum commit'
        $git = (Get-Command git -CommandType Application -TotalCount 1).Source
        $got = Invoke-Captured $git @('-C', $checkout, 'fetch', '--no-tags', '--force', 'origin', "refs/tags/${Tag}:refs/tags/${Tag}")
        Assert-True ($got.Code -eq 0) 'restore annotated public tag'
        foreach ($arguments in @(
            @('cat-file', '-t', "refs/tags/$Tag"),
            @('rev-parse', 'HEAD'),
            @('rev-parse', "refs/tags/$Tag^{commit}"),
            @('diff-tree', '--no-commit-id', '--name-status', '-r', 'HEAD')
        )) {
            $got = Invoke-Captured $git (@('-C', $checkout) + $arguments)
            Assert-True ($got.Code -eq 0) 'public source boundary command succeeds'
            $text = $utf8.GetString($got.Out).Trim()
            $expected = if ($arguments[0] -eq 'cat-file') { 'tag' } elseif ($arguments[0] -eq 'diff-tree') { "A`tdist/checksums-v$version.txt" } else { $Commit }
            Assert-True ($text -ceq $expected) 'tag, C and checksum-only child boundary'
        }
        $got = Invoke-Captured $git @('-C', $checkout, 'rev-list', '--parents', '-n', '1', 'HEAD')
        Assert-True ($got.Code -eq 0 -and $utf8.GetString($got.Out).Trim().Split(' ').Count -eq 2) 'exactly one source parent'
        Assert-True ([IO.File]::ReadAllText((Join-Path $checkout "dist/checksums-v$version.txt")) -ceq $manifest) 'candidate bytes equal authenticated C manifest'
        $got = Invoke-Captured $shell $installArgs
        Assert-True ($got.Code -eq 0) 'real public standalone install'
    } else {
        New-PrivateDirectory $destination
        Copy-Item -LiteralPath (Join-Path $Assets $asset) -Destination $binary
        Protect-Path $binary $false
    }
    Assert-InstallAcl $destination $true
    Assert-InstallAcl $binary $false
    Assert-True ((Hash $binary) -ceq (Hash (Join-Path $Assets $asset))) 'installed payload equals integrated candidate'
    Assert-Pe $binary
    Assert-Version $binary

    # cmd invocation is independent of either PowerShell edition's native argv.
    $cmdScript = Join-Path $root 'version.cmd'
    Assert-True ($binary -notmatch '["%\r\n]') 'literal cmd fixture path'
    Write-PrivateFile $cmdScript ("@echo off`r`n`"$binary`" version`r`nexit /b %errorlevel%`r`n")
    $got = Invoke-Captured (Join-Path $env:SystemRoot 'System32\cmd.exe') @('/d', '/c', 'version.cmd')
    Assert-True ($got.Code -eq 0 -and $utf8.GetString($got.Out).Trim() -ceq "secret $version (go)") 'cmd version invocation'

    $store = Join-Path $root 'synthetic store.secret'
    Write-PrivateFile $store ("PLUGIN_TOKEN=" + $script:Value + "`n")
    Assert-Private $store
    $frames = @(
        @{ jsonrpc = '2.0'; id = 1; method = 'initialize'; params = @{ protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'synthetic-release'; version = '1' } } },
        @{ jsonrpc = '2.0'; method = 'notifications/initialized' },
        @{ jsonrpc = '2.0'; id = 2; method = 'tools/list' },
        @{ jsonrpc = '2.0'; id = 3; method = 'tools/call'; params = @{ name = 'list'; arguments = @{} } },
        @{ jsonrpc = '2.0'; id = 4; method = 'tools/call'; params = @{ name = 'health'; arguments = @{} } }
    )
    $inputText = (($frames | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 10 -Compress }) -join "`n") + "`n"
    $got = Invoke-Captured $binary @('mcp', '--store', ('file:' + $store)) $inputText
    Assert-True ($got.Code -eq 0 -and $got.Err.Length -eq 0) 'names-only MCP transport'
    $replies = @($utf8.GetString($got.Out).Trim().Split("`n") | ForEach-Object { $_ | ConvertFrom-Json })
    Assert-True ($replies.Count -eq 4) 'all MCP replies present'
    for ($index = 0; $index -lt 4; $index++) {
        Assert-True ($replies[$index].id -eq ($index + 1) -and
            $null -eq $replies[$index].PSObject.Properties['error']) 'ordered successful JSON-RPC replies'
    }
    Assert-True ($replies[0].result.serverInfo.version -ceq '1') 'metadata protocol version is not release version'
    $names = @($replies[1].result.tools | ForEach-Object { $_.name } | Sort-Object)
    Assert-True (($names -join ',') -ceq 'diff,health,list,show') 'exact read-only tool inventory'
    foreach ($tool in $replies[1].result.tools) { Assert-True $tool.annotations.readOnlyHint 'read-only tool hint' }
    $inventory = $replies[2].result.content[0].text | ConvertFrom-Json
    Assert-True ($inventory.version -eq 1 -and $inventory.stores.Count -eq 1 -and
        $inventory.stores[0].records.Count -eq 1 -and
        $inventory.stores[0].records[0].key -ceq 'PLUGIN_TOKEN') 'synthetic names-only list'
    $health = $replies[3].result.content[0].text | ConvertFrom-Json
    Assert-True ($health.version -eq 1 -and $health.status -ceq 'ready' -and $health.stores -eq 1) 'configured metadata health only'

    $child = Join-Path $root 'redacted child.ps1'
    Write-PrivateFile $child '[Console]::Out.WriteLine($env:PLUGIN_TOKEN); [Console]::Error.WriteLine($env:PLUGIN_TOKEN)'
    $got = Invoke-Captured $binary @('run', '-f', ('file:' + $store), '--key', 'PLUGIN_TOKEN', '--',
        $shell, '-NoProfile', '-NonInteractive', '-File', $child)
    Assert-True ($got.Code -eq 0 -and $utf8.GetString($got.Out).Contains('<redacted>') -and
        $utf8.GetString($got.Err).Contains('<redacted>')) 'run redacts both streams'

    if ($Published) {
        $before = Hash $binary
        $replacementArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $installer,
            '--version', $version, '--dir', $destination)
        $got = Invoke-Captured $shell $replacementArgs
        Assert-True ($got.Code -eq 0 -and (Hash $binary) -ceq $before) 'verified public replacement with attestation-derived C'
        $badArgs = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $installer,
            '--version', '0.3.0/invalid', '--commit', $Commit, '--dir', $destination)
        $got = Invoke-Captured $shell $badArgs
        Assert-True ($got.Code -ne 0 -and (Hash $binary) -ceq $before) 'failed install preserves existing binary'
        Assert-InstallAcl $binary $false
        Assert-Version $binary
    }
    $evidence = if ($Published) { 'public verified standalone install' } else { 'synthetic integrated candidate payload install, not provenance' }
    Write-Output ("PASS $ExpectedArchitecture $evidence, ACL, PE, cmd, MCP list/health and redacted run; no installed-hook claim")
} finally {
    # The approved installer edits user PATH. Restore it even after a failed test;
    # these runs never leave a registration, profile or PATH entry on the runner.
    try {
        if ($null -ne $userPathKey) {
            if ($null -eq $userPath) {
                if ($userPathKey.GetValueNames() -contains 'Path') {
                    Remove-ItemProperty -LiteralPath 'HKCU:\Environment' -Name Path
                }
            } else {
                $null = New-ItemProperty -LiteralPath 'HKCU:\Environment' -Name Path -Value $userPath -PropertyType ($userPathKind.ToString()) -Force
            }
            $userPathKey.Dispose()
        }
    } finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
    }
}
